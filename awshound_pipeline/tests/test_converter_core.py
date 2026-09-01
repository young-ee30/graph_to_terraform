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
        files = MODULE.terraform_files(scenario, nodes, edges, None)
        coverage = json.loads(files["terraform-coverage.json"])
        self.assertEqual(coverage["overall"], "CONTEXT_REQUIRED")
        self.assertTrue(
            any(value.startswith("APP_WORKLOAD_BINDING_REQUIRED") for value in coverage["blockers"])
        )


if __name__ == "__main__":
    unittest.main()
