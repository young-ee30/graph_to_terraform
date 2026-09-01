import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "mirrorctl.py"
SPEC = importlib.util.spec_from_file_location("mirrorctl_module", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


ACCOUNT = "111122223333"
REGION = "us-east-1"


def node(node_id, kind, arn, **props):
    return {
        "id": node_id,
        "kinds": [kind],
        "properties": {"arn": arn, "account_id": ACCOUNT, **props},
    }


def edge(kind, start, end, **props):
    return {
        "kind": kind,
        "start": {"value": start},
        "end": {"value": end},
        "properties": props,
    }


def fixture_graph():
    account = "account"
    admin = "admin-policy"
    lu, lf, lr, lp = "lambda-user", "lambda-function", "lambda-role", "lambda-flag"
    su, sr, sp = "sts-user", "sts-role", "sts-flag"
    eu, er, ep = "ec2-user", "ec2-role", "ec2-flag"
    ku, kt, kb, ko = "key-user", "key-target", "key-bucket", "key-object"
    cu, r1, r2, r3, cb, co = "chain-user", "chain-r1", "chain-r2", "chain-r3", "chain-bucket", "chain-object"
    nodes = [
        node(account, "AWS_Account", f"arn:aws:iam::{ACCOUNT}:root", name=ACCOUNT),
        node(admin, "AWS_Policy", "arn:aws:iam::aws:policy/AdministratorAccess", policy_name="AdministratorAccess", account_id="aws"),
        node(lu, "AWS_User", f"arn:aws:iam::{ACCOUNT}:user/test-lambda-004-starting-user", user_name="test-lambda-004-starting-user"),
        node(lf, "AWS_LambdaFunction", f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:test-lambda-004", name=f"{ACCOUNT}:test-lambda-004", region=REGION, runtime="python3.11", handler="lambda_function.lambda_handler", memory_size=128, timeout=10),
        node(lr, "AWS_Role", f"arn:aws:iam::{ACCOUNT}:role/test-lambda-004-role", role_name="test-lambda-004-role"),
        node(lp, "AWS_SSMParameter", f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter/test/lambda-004", name=f"{ACCOUNT}:/test/lambda-004", region=REGION),
        node(su, "AWS_User", f"arn:aws:iam::{ACCOUNT}:user/test-sts-001-starting-user", user_name="test-sts-001-starting-user"),
        node(sr, "AWS_Role", f"arn:aws:iam::{ACCOUNT}:role/test-sts-001-role", role_name="test-sts-001-role"),
        node(sp, "AWS_SSMParameter", f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter/test/sts-001", name=f"{ACCOUNT}:/test/sts-001", region=REGION),
        node(eu, "AWS_User", f"arn:aws:iam::{ACCOUNT}:user/test-ec2-004-starting-user", user_name="test-ec2-004-starting-user"),
        node(er, "AWS_Role", f"arn:aws:iam::{ACCOUNT}:role/test-ec2-004-role", role_name="test-ec2-004-role"),
        node(ep, "AWS_SSMParameter", f"arn:aws:ssm:{REGION}:{ACCOUNT}:parameter/test/ec2-004", name=f"{ACCOUNT}:/test/ec2-004", region=REGION),
        node(ku, "AWS_User", f"arn:aws:iam::{ACCOUNT}:user/test-iam-002-privesc", user_name="test-iam-002-to-bucket-privesc-user"),
        node(kt, "AWS_User", f"arn:aws:iam::{ACCOUNT}:user/test-iam-002-access", user_name="test-iam-002-to-bucket-access-user"),
        node(kb, "AWS_S3Bucket", "arn:aws:s3:::test-key-bucket", name=f"{ACCOUNT}:test-key-bucket", region=REGION),
        node(ko, "AWS_S3Object", "arn:aws:s3:::test-key-bucket/flag.txt", name=f"{ACCOUNT}:test-key-bucket/flag.txt", bucket_name="test-key-bucket", region=REGION),
        node(cu, "AWS_User", f"arn:aws:iam::{ACCOUNT}:user/test-role-chain-to-s3", user_name="test-role-chain-to-s3"),
        node(r1, "AWS_Role", f"arn:aws:iam::{ACCOUNT}:role/chain-1", role_name="chain-1"),
        node(r2, "AWS_Role", f"arn:aws:iam::{ACCOUNT}:role/chain-2", role_name="chain-2"),
        node(r3, "AWS_Role", f"arn:aws:iam::{ACCOUNT}:role/chain-3", role_name="chain-3"),
        node(cb, "AWS_S3Bucket", "arn:aws:s3:::test-chain-bucket", name=f"{ACCOUNT}:test-chain-bucket", region=REGION),
        node(co, "AWS_S3Object", "arn:aws:s3:::test-chain-bucket/flag.txt", name=f"{ACCOUNT}:test-chain-bucket/flag.txt", bucket_name="test-chain-bucket", region=REGION),
    ]
    edges = [
        edge("AWS_CanUpdateLambdaCode", lu, lf),
        edge("AWS_CanInvokeLambdaFunction", lu, lf),
        edge("AWS_RunsAs", lf, lr),
        edge("AWS_HasPolicy", lr, admin),
        edge("AWS_CanGetParameter", lr, lp),
        edge("AWS_CanAssumeRole", su, sr),
        edge("AWS_HasPolicy", sr, admin),
        edge("AWS_CanGetParameter", sr, sp),
        edge("AWS_CanPassRoleToService", eu, er, services="ec2"),
        edge("AWS_CanRequestSpotInstances", eu, account),
        edge("AWS_HasPolicy", er, admin),
        edge("AWS_CanGetParameter", er, ep),
        edge("AWS_CanCreateAccessKey", ku, kt),
        edge("AWS_CanGetObject", kt, ko),
        edge("AWS_Contains", kb, ko),
        edge("AWS_CanAssumeRole", cu, r1),
        edge("AWS_CanAssumeRole", r1, r2),
        edge("AWS_CanAssumeRole", r2, r3),
        edge("AWS_CanGetObject", r3, co),
        edge("AWS_Contains", cb, co),
    ]
    return {"graph": {"nodes": nodes, "edges": edges}, "metadata": {"source_kind": "AWS"}}


class MirrorCtlTests(unittest.TestCase):
    def test_synthetic_ssm_ec2_s3_fixture_classification(self):
        fixture = MODULE_PATH.parent / "fixtures" / "synthetic-ssm-ec2-s3-graph.json"
        document, _ = MODULE.load_graph(fixture)
        nodes, edges = MODULE.normalize_graph(document)
        paths = MODULE.extract_attack_paths(
            nodes,
            edges,
            source_selectors=None,
            target_selectors=["synthetic-sensitive-bucket/flag.txt"],
            max_depth=5,
            limit=5,
        )
        self.assertEqual(len(paths), 1)
        self.assertEqual(
            [edge.kind for edge in paths[0]["path_edges"]],
            ["AWS_SSMCanStartSession", "AWS_RunsAs", "AWS_CanGetObject"],
        )
        extracted = MODULE.extracted_path_document(paths[0], nodes, "fixture", 1)
        extracted_nodes, extracted_edges = MODULE.normalize_graph(extracted)
        scenario = MODULE.detect_scenarios(extracted_nodes, extracted_edges)[0]
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
        contract = MODULE.validation_contract_for(
            scenario, extracted_nodes, extracted_edges
        )
        self.assertEqual(len(contract["steps"]), 3)
        self.assertEqual(
            contract["automation_status"], "EXECUTOR_IMPLEMENTATION_REQUIRED"
        )

    def test_official_non_structural_edges_have_action_mapping(self):
        catalog = MODULE.official_edge_catalog()
        self.assertEqual(len(catalog), 156)
        missing = [
            name
            for name, item in catalog.items()
            if not item["structural"] and not item["actions"]
        ]
        self.assertEqual(missing, [])

    def test_detects_five_supported_scenarios(self):
        nodes, edges = MODULE.normalize_graph(fixture_graph())
        scenarios = MODULE.detect_scenarios(nodes, edges)
        self.assertEqual(len(scenarios), 5)
        self.assertEqual(
            {item.scenario_type for item in scenarios},
            {
                "lambda_update_invoke_admin",
                "sts_assume_admin",
                "ec2_passrole_spot_admin",
                "iam_create_access_key_s3",
                "role_chain_s3",
            },
        )
        ec2 = next(item for item in scenarios if item.scenario_type == "ec2_passrole_spot_admin")
        self.assertIn("L4_NETWORK", ec2.layers)

    def test_context_plan_is_read_only(self):
        nodes, edges = MODULE.normalize_graph(fixture_graph())
        scenario = next(
            item for item in MODULE.detect_scenarios(nodes, edges)
            if item.scenario_type == "lambda_update_invoke_admin"
        )
        requests = MODULE.context_plan(scenario, nodes, edges)
        self.assertTrue(requests)
        self.assertTrue(all(not request.mutating for request in requests))
        operations = {(request.service, request.operation) for request in requests}
        self.assertIn(("lambda", "get-function"), operations)
        self.assertIn(("iam", "simulate-principal-policy"), operations)

    def test_extracts_ranked_path_and_writes_single_graph_zip(self):
        document = fixture_graph()
        nodes, edges = MODULE.normalize_graph(document)
        paths = MODULE.extract_attack_paths(
            nodes,
            edges,
            source_selectors=["test-lambda-004-starting-user"],
            target_selectors=["test-lambda-004-role"],
            max_depth=4,
            limit=5,
        )
        self.assertTrue(paths)
        self.assertEqual(paths[0]["source"], "lambda-user")
        self.assertEqual(paths[0]["target"], "lambda-role")
        self.assertEqual(
            [item.kind for item in paths[0]["path_edges"]],
            ["AWS_CanUpdateLambdaCode", "AWS_RunsAs"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "paths"
            result = MODULE.write_extracted_paths(
                output, paths, nodes, "source-sha", False
            )
            self.assertEqual(result["path_count"], len(paths))
            with zipfile.ZipFile(output / "path-001.zip") as archive:
                self.assertEqual(archive.namelist(), ["graph.json"])
                extracted = json.loads(archive.read("graph.json"))
            kinds = {
                kind
                for item in extracted["graph"]["nodes"]
                for kind in item.get("kinds", [])
            }
            self.assertIn("AWS_LambdaFunction", kinds)
            self.assertIn("AWS_Role", kinds)

    def test_generates_all_terraform_directories(self):
        document = fixture_graph()
        nodes, edges = MODULE.normalize_graph(document)
        scenarios = MODULE.detect_scenarios(nodes, edges)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for scenario in scenarios:
                requests = MODULE.context_plan(scenario, nodes, edges)
                destination = MODULE.generate_scenario_directory(
                    root, scenario, nodes, edges, requests, "fixture-sha256"
                )
                self.assertTrue((destination / "main.tf").is_file())
                self.assertTrue((destination / "variables.tf").is_file())
                self.assertTrue((destination / "outputs.tf").is_file())
                self.assertTrue((destination / "minimal-reproduction-spec.json").is_file())
                self.assertFalse((destination / "terraform.tfvars").exists())
                text = (destination / "main.tf").read_text(encoding="utf-8")
                self.assertIn('ManagedBy = "awshound-mirror"', text)

    def test_zip_requires_exactly_one_graph_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("graph.json", json.dumps(fixture_graph()))
                archive.writestr("extra.txt", "not allowed")
            with self.assertRaises(MODULE.PipelineError):
                MODULE.load_graph(path)

    def test_unknown_official_edge_uses_generic_registry_renderer(self):
        user_id = "generic-user"
        role_id = "generic-role"
        document = {
            "graph": {
                "nodes": [
                    node(
                        user_id,
                        "AWS_User",
                        f"arn:aws:iam::{ACCOUNT}:user/generic-starting-user",
                        user_name="generic-starting-user",
                    ),
                    node(
                        role_id,
                        "AWS_Role",
                        f"arn:aws:iam::{ACCOUNT}:role/generic-target-role",
                        role_name="generic-target-role",
                        assume_role_policy_document=json.dumps(
                            {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:user/generic-starting-user"},
                                        "Action": "sts:AssumeRole",
                                    }
                                ],
                            }
                        ),
                    ),
                ],
                "edges": [edge("AWS_CanUpdateAssumeRolePolicy", user_id, role_id)],
            },
            "metadata": {"source_kind": "AWS"},
        }
        nodes, edges = MODULE.normalize_graph(document)
        scenarios = MODULE.detect_scenarios(nodes, edges)
        self.assertEqual(len(scenarios), 1)
        self.assertEqual(scenarios[0].scenario_type, "generic_awshound_path")
        files = MODULE.generic_terraform(scenarios[0], nodes, edges)
        self.assertIn("iam:UpdateAssumeRolePolicy", files["main.tf"])
        coverage = json.loads(files["terraform-coverage.json"])
        self.assertEqual(coverage["overall"], "SEMANTIC_MIRROR_READY")
        contract = MODULE.validation_contract_for(scenarios[0], nodes, edges)
        self.assertEqual(contract["required_terminal_state"], "EXECUTION_VERIFIED")
        self.assertEqual(contract["automation_status"], "EXECUTOR_IMPLEMENTATION_REQUIRED")
        self.assertIn(
            "BOUNDED_RUNTIME_ADAPTER:generic_awshound_path",
            contract["missing_automation"],
        )

    def test_high_fidelity_path_generates_auto_executable_contract(self):
        nodes, edges = MODULE.normalize_graph(fixture_graph())
        scenario = next(
            item
            for item in MODULE.detect_scenarios(nodes, edges)
            if item.scenario_type == "sts_assume_admin"
        )
        contract = MODULE.validation_contract_for(scenario, nodes, edges)
        self.assertEqual(contract["automation_status"], "AUTO_EXECUTABLE")
        self.assertFalse(contract["missing_automation"])

    def test_network_context_renders_vpc_subnet_and_security_group(self):
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
                                "AvailabilityZoneId": "use1-az1",
                                "MapPublicIpOnLaunch": False,
                            }
                        ]
                    },
                },
                {
                    "status": "COLLECTED",
                    "request": {"operation": "describe-security-groups"},
                    "response": {
                        "SecurityGroups": [
                            {
                                "GroupId": "sg-1234",
                                "GroupName": "mirror-sg",
                                "VpcId": "vpc-1234",
                                "Description": "test",
                            }
                        ]
                    },
                },
                {
                    "status": "COLLECTED",
                    "request": {"operation": "describe-security-group-rules"},
                    "response": {
                        "SecurityGroupRules": [
                            {
                                "SecurityGroupRuleId": "sgr-1234",
                                "GroupId": "sg-1234",
                                "IsEgress": True,
                                "IpProtocol": "tcp",
                                "FromPort": 443,
                                "ToPort": 443,
                                "CidrIpv4": "0.0.0.0/0",
                            }
                        ]
                    },
                },
            ]
        }
        hcl, subnet_refs, sg_refs, coverage, blockers = MODULE.render_network_from_context(evidence)
        self.assertIn('resource "aws_vpc"', hcl)
        self.assertIn('resource "aws_subnet"', hcl)
        self.assertIn('resource "aws_vpc_security_group_egress_rule"', hcl)
        self.assertIn("subnet-1234", subnet_refs)
        self.assertIn("sg-1234", sg_refs)
        self.assertFalse(blockers)
        self.assertTrue(coverage)

    def test_generic_ec2_uses_collected_network_references(self):
        user_id = "ec2-generic-user"
        instance_id = "ec2-generic-instance"
        document = {
            "graph": {
                "nodes": [
                    node(
                        user_id,
                        "AWS_User",
                        f"arn:aws:iam::{ACCOUNT}:user/ec2-generic-user",
                        user_name="ec2-generic-user",
                    ),
                    node(
                        instance_id,
                        "AWS_EC2Instance",
                        f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-1234",
                        instance_id="i-1234",
                        instance_type="t3.micro",
                        image_id="ami-1234",
                        vpc_id="vpc-1234",
                        subnet_id="subnet-1234",
                        security_groups=json.dumps([{"GroupId": "sg-1234", "GroupName": "mirror-sg"}]),
                        region=REGION,
                    ),
                ],
                "edges": [edge("AWS_SSMCanStartSession", user_id, instance_id)],
            },
            "metadata": {"source_kind": "AWS"},
        }
        nodes, edges = MODULE.normalize_graph(document)
        scenario = MODULE.detect_scenarios(nodes, edges)[0]
        evidence = {
            "results": [
                {"status": "COLLECTED", "request": {"operation": "describe-vpcs"}, "response": {"Vpcs": [{"VpcId": "vpc-1234", "CidrBlock": "10.0.0.0/16", "InstanceTenancy": "default"}]}},
                {"status": "COLLECTED", "request": {"operation": "describe-subnets"}, "response": {"Subnets": [{"SubnetId": "subnet-1234", "VpcId": "vpc-1234", "CidrBlock": "10.0.1.0/24", "AvailabilityZoneId": "use1-az1"}]}},
                {"status": "COLLECTED", "request": {"operation": "describe-security-groups"}, "response": {"SecurityGroups": [{"GroupId": "sg-1234", "GroupName": "mirror-sg", "VpcId": "vpc-1234", "Description": "test"}]}},
            ]
        }
        files = MODULE.generic_terraform(scenario, nodes, edges, evidence)
        main = files["main.tf"]
        self.assertIn("aws_instance", main)
        self.assertIn("aws_subnet.subnet_subnet_1234.id", main)
        self.assertIn("aws_security_group.sg_sg_1234.id", main)
        self.assertNotIn('resource "aws_vpc" "generic"', main)


if __name__ == "__main__":
    unittest.main()
