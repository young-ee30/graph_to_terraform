import importlib.util
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "converter_core.py"
SPEC = importlib.util.spec_from_file_location("converter_core_test_module", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ConverterCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = ROOT / "fixtures" / "synthetic-ssm-ec2-s3-graph.json"
        cls.document, _ = MODULE.load_graph(fixture)
        cls.nodes, cls.edges = MODULE.normalize_graph(cls.document)

    def test_bundled_official_schema_registry(self):
        catalog = MODULE.official_edge_catalog()
        self.assertEqual(len(catalog), 156)
        missing = [
            name
            for name, item in catalog.items()
            if not item["structural"] and not item["actions"]
        ]
        self.assertEqual(missing, [])

    def test_detects_generic_attack_path(self):
        scenarios = MODULE.detect_scenarios(self.nodes, self.edges)
        self.assertTrue(scenarios)
        scenario = scenarios[0]
        self.assertEqual(scenario.scenario_type, "generic_awshound_path")
        self.assertEqual(
            set(scenario.layers),
            {
                "L1_IAM_CONTROL_PLANE",
                "L2_WORKLOAD_RUNTIME",
                "L3_APPLICATION_DATA",
                "L4_NETWORK",
            },
        )

    def test_context_plan_uses_read_only_node_apis(self):
        scenario = MODULE.detect_scenarios(self.nodes, self.edges)[0]
        requests = MODULE.context_plan(scenario, self.nodes, self.edges)
        self.assertTrue(requests)
        self.assertTrue(all(not request.mutating for request in requests))
        operations = {(request.service, request.operation) for request in requests}
        self.assertIn(("ec2", "describe-instances"), operations)
        self.assertIn(("ec2", "describe-security-group-rules"), operations)
        self.assertIn(("s3api", "head-object"), operations)

    def test_generic_terraform_generation(self):
        scenario = MODULE.detect_scenarios(self.nodes, self.edges)[0]
        files = MODULE.terraform_files(scenario, self.nodes, self.edges, None)
        self.assertIn("main.tf", files)
        self.assertIn("variables.tf", files)
        self.assertIn("outputs.tf", files)
        self.assertIn("terraform-coverage.json", files)
        self.assertIn("ssm:StartSession", files["main.tf"])
        self.assertIn("s3:GetObject", files["main.tf"])
        coverage = json.loads(files["terraform-coverage.json"])
        self.assertEqual(coverage["overall"], "CONTEXT_REQUIRED")

    def test_network_context_renderer(self):
        evidence = {
            "results": [
                {
                    "status": "COLLECTED",
                    "request": {"operation": "describe-vpcs"},
                    "response": {
                        "Vpcs": [
                            {
                                "VpcId": "vpc-1234",
                                "CidrBlock": "10.0.0.0/16",
                                "InstanceTenancy": "default",
                            }
                        ]
                    },
                },
                {
                    "status": "COLLECTED",
                    "request": {"operation": "describe-subnets"},
                    "response": {
                        "Subnets": [
                            {
                                "SubnetId": "subnet-1234",
                                "VpcId": "vpc-1234",
                                "CidrBlock": "10.0.1.0/24",
                            }
                        ]
                    },
                },
            ]
        }
        hcl, subnet_refs, _, coverage, blockers = MODULE.render_network_from_context(
            evidence
        )
        self.assertIn('resource "aws_vpc"', hcl)
        self.assertIn('resource "aws_subnet"', hcl)
        self.assertIn("subnet-1234", subnet_refs)
        self.assertTrue(coverage)
        self.assertFalse(blockers)

    def test_integrated_rnr_path_detection_and_context(self):
        fixture = ROOT / "fixtures" / "synthetic-integrated-rnr-path.json"
        document, _ = MODULE.load_graph(fixture)
        nodes, edges = MODULE.normalize_graph(document)
        scenarios = MODULE.detect_scenarios(nodes, edges)
        self.assertEqual(len(scenarios), 1)
        scenario = scenarios[0]
        self.assertEqual(scenario.scenario_type, "integrated_rnr_path")
        self.assertEqual(
            set(scenario.layers),
            {"L1_IAM_CONTROL_PLANE", "L3_APPLICATION_DATA", "L4_NETWORK"},
        )
        operations = {
            (request.service, request.operation)
            for request in MODULE.context_plan(scenario, nodes, edges)
        }
        self.assertIn(("elbv2", "describe-load-balancers"), operations)
        self.assertIn(("elbv2", "describe-listeners"), operations)
        self.assertIn(("ec2", "describe-security-groups"), operations)
        self.assertIn(("ecs", "list-clusters"), operations)
        files = MODULE.terraform_files(scenario, nodes, edges, None)
        coverage = json.loads(files["terraform-coverage.json"])
        self.assertEqual(coverage["overall"], "CONTEXT_REQUIRED")
        self.assertTrue(
            any(value.startswith("APP_WORKLOAD_BINDING_REQUIRED") for value in coverage["blockers"])
        )

    def test_mirror_spec_expands_ecs_and_ecr_read_only_requests(self):
        fixture = ROOT / "fixtures" / "synthetic-integrated-rnr-path.json"
        document, _ = MODULE.load_graph(fixture)
        nodes, edges = MODULE.normalize_graph(document)
        scenario = MODULE.detect_scenarios(nodes, edges)[0]
        spec = {
            "selected_runtime_path": {
                "frontend_task_id": "a" * 32,
                "frontend_private_ip": "10.0.1.10",
            },
            "project": "test-project",
        }
        requests = MODULE.context_plan(scenario, nodes, edges, spec)
        operations = {(value.service, value.operation) for value in requests}
        self.assertIn(("ecs", "list-clusters"), operations)
        self.assertIn(("resourcegroupstaggingapi", "get-resources"), operations)

        cluster_request = next(
            value
            for value in requests
            if value.service == "ecs" and value.operation == "list-clusters"
        )
        expanded = MODULE.expand_context_response(
            cluster_request,
            {"clusterArns": ["arn:aws:ecs:ap-northeast-2:111122223333:cluster/test"]},
        )
        self.assertIn(
            ("ecs", "describe-tasks"),
            {(value.service, value.operation) for value in expanded},
        )

        task_definition_request = MODULE.ContextRequest(
            request_id="ctx-test",
            service="ecs",
            operation="describe-task-definition",
            arguments=["--task-definition", "test:1"],
            reason="test",
            required=True,
            region="ap-northeast-2",
        )
        image_requests = MODULE.expand_context_response(
            task_definition_request,
            {
                "taskDefinition": {
                    "containerDefinitions": [
                        {
                            "image": "111122223333.dkr.ecr.ap-northeast-2.amazonaws.com/test/frontend:v1",
                            "secrets": [
                                {
                                    "name": "PASSWORD",
                                    "valueFrom": "arn:aws:secretsmanager:ap-northeast-2:111122223333:secret:test",
                                }
                            ],
                        }
                    ]
                }
            },
        )
        image_operations = {(value.service, value.operation) for value in image_requests}
        self.assertIn(("ecr", "describe-images"), image_operations)
        self.assertIn(("ecr", "batch-get-image"), image_operations)
        self.assertIn(("secretsmanager", "describe-secret"), image_operations)
        self.assertNotIn(("secretsmanager", "get-secret-value"), image_operations)

    def test_context_command_rejects_mutating_operation(self):
        request = MODULE.ContextRequest(
            request_id="ctx-unsafe",
            service="ecs",
            operation="update-service",
            arguments=[],
            reason="unsafe test",
            required=True,
            region="ap-northeast-2",
        )
        with self.assertRaises(MODULE.PipelineError):
            MODULE.aws_cli_command(request, "readonly")

    def test_integrated_context_renders_ecs_alb_and_waf(self):
        fixture = ROOT / "fixtures" / "synthetic-integrated-rnr-path.json"
        document, _ = MODULE.load_graph(fixture)
        nodes, edges = MODULE.normalize_graph(document)
        scenario = MODULE.detect_scenarios(nodes, edges)[0]
        cluster_arn = "arn:aws:ecs:ap-northeast-2:111122223333:cluster/test"
        service_arn = "arn:aws:ecs:ap-northeast-2:111122223333:service/test/frontend"
        task_arn = "arn:aws:ecs:ap-northeast-2:111122223333:task-definition/frontend:1"
        lb_arn = nodes["alb"].properties["arn"]
        tg_arn = "arn:aws:elasticloadbalancing:ap-northeast-2:111122223333:targetgroup/frontend/abc"
        listener_arn = "arn:aws:elasticloadbalancing:ap-northeast-2:111122223333:listener/app/lab/abc/def"

        def result(operation, response):
            return {
                "status": "COLLECTED",
                "request": {"operation": operation},
                "response": response,
            }

        evidence = {
            "results": [
                result("describe-vpcs", {"Vpcs": [{"VpcId": "vpc-test", "CidrBlock": "10.0.0.0/16"}]}),
                result("describe-subnets", {"Subnets": [
                    {"SubnetId": "subnet-a", "VpcId": "vpc-test", "CidrBlock": "10.0.1.0/24", "AvailabilityZone": "ap-northeast-2a"},
                    {"SubnetId": "subnet-b", "VpcId": "vpc-test", "CidrBlock": "10.0.2.0/24", "AvailabilityZone": "ap-northeast-2b"},
                ]}),
                result("describe-security-groups", {"SecurityGroups": [{"GroupId": "sg-0123456789abcdef0", "VpcId": "vpc-test", "GroupName": "alb", "Description": "test"}]}),
                result("describe-clusters", {"clusters": [{"clusterArn": cluster_arn, "clusterName": "test"}]}),
                result("describe-services", {"services": [{
                    "serviceArn": service_arn,
                    "serviceName": "frontend",
                    "clusterArn": cluster_arn,
                    "taskDefinition": task_arn,
                    "launchType": "EC2",
                    "networkConfiguration": {"awsvpcConfiguration": {"subnets": ["subnet-a", "subnet-b"], "securityGroups": ["sg-0123456789abcdef0"]}},
                    "loadBalancers": [{"targetGroupArn": tg_arn, "containerName": "frontend", "containerPort": 80}],
                }]}),
                result("describe-task-definition", {"taskDefinition": {
                    "taskDefinitionArn": task_arn,
                    "family": "frontend",
                    "networkMode": "awsvpc",
                    "requiresCompatibilities": ["EC2"],
                    "taskRoleArn": nodes["role"].arn,
                    "containerDefinitions": [{"name": "frontend", "image": "111122223333.dkr.ecr.ap-northeast-2.amazonaws.com/test/frontend:v1", "essential": True, "portMappings": [{"containerPort": 80, "protocol": "tcp"}]}],
                }}),
                {
                    "status": "COLLECTED",
                    "request": {"service": "ecr", "operation": "batch-get-image", "arguments": ["--repository-name", "test/frontend"]},
                    "response": {"images": [{"imageId": {"imageDigest": "sha256:" + "a" * 64}}]},
                },
                result("describe-load-balancers", {"LoadBalancers": [{"LoadBalancerArn": lb_arn, "Scheme": "internet-facing", "Type": "application", "AvailabilityZones": [{"SubnetId": "subnet-a"}, {"SubnetId": "subnet-b"}], "SecurityGroups": ["sg-0123456789abcdef0"]}]}),
                result("describe-target-groups", {"TargetGroups": [{"TargetGroupArn": tg_arn, "TargetGroupName": "frontend", "Port": 80, "Protocol": "HTTP", "TargetType": "ip", "VpcId": "vpc-test"}]}),
                result("describe-listeners", {"Listeners": [{"ListenerArn": listener_arn, "LoadBalancerArn": lb_arn, "Port": 80, "Protocol": "HTTP", "DefaultActions": [{"Type": "forward", "TargetGroupArn": tg_arn}]}]}),
            ]
        }
        spec = {
            "selected_runtime_path": {"frontend_task_id": "a" * 32},
            "steps": [{"step": 1}],
        }
        files = MODULE.terraform_files(scenario, nodes, edges, evidence, spec)
        main = files["main.tf"]
        self.assertIn('resource "aws_ecs_cluster"', main)
        self.assertIn('resource "aws_ecs_task_definition"', main)
        self.assertIn('resource "aws_ecs_service"', main)
        self.assertIn('resource "aws_lb"', main)
        self.assertIn('resource "aws_wafv2_web_acl"', main)
        self.assertNotIn("default_action { block {} }", main)
        self.assertNotIn("action { allow {} }", main)

    def test_generic_node_kinds_select_service_specific_apis(self):
        nodes = [
            MODULE.Node(
                id="service",
                kinds=("AWS_ECSService",),
                properties={
                    "arn": "arn:aws:ecs:ap-northeast-2:111122223333:service/cluster/orders",
                    "name": "orders",
                },
            ),
            MODULE.Node(
                id="database",
                kinds=("AWS_Database",),
                properties={
                    "arn": "arn:aws:rds:ap-northeast-2:111122223333:db:orders",
                    "name": "orders",
                },
            ),
            MODULE.Node(
                id="secret",
                kinds=("AWS_Secret",),
                properties={
                    "arn": "arn:aws:secretsmanager:ap-northeast-2:111122223333:secret:orders",
                    "name": "orders",
                },
            ),
        ]
        operations = {
            (request.service, request.operation)
            for node in nodes
            for request in MODULE.node_context_requests(node, "ap-northeast-2")
        }
        self.assertIn(("ecs", "describe-services"), operations)
        self.assertIn(("rds", "describe-db-instances"), operations)
        self.assertIn(("secretsmanager", "describe-secret"), operations)
        self.assertNotIn(("secretsmanager", "get-secret-value"), operations)

    def test_context_response_sanitizes_sensitive_runtime_values(self):
        task_request = MODULE.ContextRequest(
            request_id="ctx-task",
            service="ecs",
            operation="describe-task-definition",
            arguments=[],
            reason="test",
            required=True,
        )
        sanitized = MODULE.sanitize_context_response(
            task_request,
            {
                "taskDefinition": {
                    "containerDefinitions": [
                        {
                            "environment": [
                                {"name": "APP_MODE", "value": "lab"},
                                {"name": "DB_PASSWORD", "value": "do-not-store"},
                            ]
                        }
                    ]
                }
            },
        )
        environment = sanitized["taskDefinition"]["containerDefinitions"][0]["environment"]
        self.assertEqual(environment[0]["value"], "lab")
        self.assertEqual(environment[1]["value"], "REDACTED_SYNTHETIC_REQUIRED")

        lambda_request = MODULE.ContextRequest(
            request_id="ctx-lambda",
            service="lambda",
            operation="get-function",
            arguments=[],
            reason="test",
            required=True,
        )
        lambda_response = MODULE.sanitize_context_response(
            lambda_request,
            {"Code": {"Location": "https://signed.example.invalid/code.zip"}},
        )
        self.assertEqual(
            lambda_response["Code"]["Location"],
            "REDACTED_EPHEMERAL_DOWNLOAD_URL",
        )

    def test_context_inventory_keeps_services_in_same_cluster(self):
        cluster = "arn:aws:ecs:ap-northeast-2:111122223333:cluster/test"
        evidence = {
            "results": [
                {
                    "status": "COLLECTED",
                    "request": {"operation": "describe-services"},
                    "response": {
                        "services": [
                            {
                                "clusterArn": cluster,
                                "serviceArn": "arn:aws:ecs:ap-northeast-2:111122223333:service/test/frontend",
                                "serviceName": "frontend",
                            },
                            {
                                "clusterArn": cluster,
                                "serviceArn": "arn:aws:ecs:ap-northeast-2:111122223333:service/test/order",
                                "serviceName": "order",
                            },
                        ]
                    },
                }
            ]
        }
        inventory = MODULE.context_inventory(evidence)
        self.assertEqual(
            {value["serviceName"] for value in inventory["ecs_services"]},
            {"frontend", "order"},
        )

    def test_empty_default_sg_and_gateway_endpoint_routes_are_not_blockers(self):
        evidence = {
            "results": [
                {
                    "status": "COLLECTED",
                    "request": {"operation": "describe-vpcs"},
                    "response": {"Vpcs": [{"VpcId": "vpc-test", "CidrBlock": "10.0.0.0/16"}]},
                },
                {
                    "status": "COLLECTED",
                    "request": {"operation": "describe-security-groups"},
                    "response": {"SecurityGroups": [{"GroupId": "sg-default", "GroupName": "default", "VpcId": "vpc-test", "IpPermissions": [], "IpPermissionsEgress": []}]},
                },
                {
                    "status": "COLLECTED",
                    "request": {"operation": "describe-route-tables"},
                    "response": {"RouteTables": [{"RouteTableId": "rtb-test", "VpcId": "vpc-test", "Associations": [], "Routes": [{"DestinationPrefixListId": "pl-test", "GatewayId": "vpce-test", "State": "active"}]}]},
                },
                {
                    "status": "COLLECTED",
                    "request": {"operation": "describe-vpc-endpoints"},
                    "response": {"VpcEndpoints": [{"VpcEndpointId": "vpce-test", "VpcId": "vpc-test", "VpcEndpointType": "Gateway", "ServiceName": "com.amazonaws.ap-northeast-2.s3", "RouteTableIds": ["rtb-test"]}]},
                },
            ]
        }
        _, _, _, coverage, blockers = MODULE.render_network_from_context(evidence)
        self.assertFalse(blockers)
        self.assertIn(
            "SAFE_DEFAULT_DENY_AUTO_CREATED",
            {value["status"] for value in coverage},
        )


if __name__ == "__main__":
    unittest.main()
