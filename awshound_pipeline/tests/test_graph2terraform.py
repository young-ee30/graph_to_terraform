import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MODULE_PATH = ROOT / "graph2terraform.py"
SPEC = importlib.util.spec_from_file_location("graph2terraform_module", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class Graph2TerraformTests(unittest.TestCase):
    def test_generation_only_converter_writes_terraform(self):
        fixture = ROOT / "fixtures" / "synthetic-ssm-ec2-s3-graph.json"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "generated"
            result = MODULE.convert(fixture, output, None, False)
            self.assertGreaterEqual(result["generated_count"], 1)
            generated = result["generated"][0]
            destination = Path(generated["directory"])
            self.assertTrue((destination / "main.tf").is_file())
            self.assertTrue((destination / "variables.tf").is_file())
            self.assertTrue((destination / "outputs.tf").is_file())
            self.assertTrue((destination / "terraform.tfvars.example").is_file())
            self.assertTrue((destination / "required-inputs.json").is_file())
            self.assertTrue((destination / "context-plan.json").is_file())
            self.assertFalse((destination / "terraform.tfvars").exists())
            manifest = json.loads(
                (destination / "conversion-manifest.json").read_text(encoding="utf-8")
            )
            self.assertFalse(manifest["safety"]["aws_connected"])
            self.assertFalse(manifest["safety"]["terraform_executed"])
            self.assertFalse(manifest["safety"]["attack_executed"])

    def test_force_refuses_unknown_output(self):
        fixture = ROOT / "fixtures" / "synthetic-ssm-ec2-s3-graph.json"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "generated"
            output.mkdir()
            (output / "user-file.txt").write_text("preserve", encoding="utf-8")
            with self.assertRaises(MODULE.ConversionError):
                MODULE.convert(fixture, output, None, True)

    def test_optional_source_profile_collects_read_only_context(self):
        fixture = ROOT / "fixtures" / "synthetic-ssm-ec2-s3-graph.json"
        fake_context = {
            "identity": {
                "Account": "111122223333",
                "Arn": "arn:aws:iam::111122223333:role/readonly-collector",
            },
            "results": [],
            "summary": {},
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "generated"
            with patch.object(MODULE.core, "collect_context", return_value=fake_context):
                result = MODULE.convert(
                    fixture,
                    output,
                    None,
                    False,
                    "source-readonly",
                )
            destination = Path(result["generated"][0]["directory"])
            self.assertTrue((destination / "context-evidence.json").is_file())
            manifest = json.loads(
                (destination / "conversion-manifest.json").read_text(encoding="utf-8")
            )
            self.assertTrue(manifest["safety"]["aws_connected"])
            self.assertEqual(
                manifest["safety"]["source_profile"], "source-readonly"
            )

    def test_integrated_rnr_graph_generates_one_path(self):
        fixture = ROOT / "fixtures" / "synthetic-integrated-rnr-path.json"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "generated"
            result = MODULE.convert(fixture, output, None, False)
            self.assertEqual(result["generated_count"], 1)
            self.assertEqual(
                result["generated"][0]["scenario_type"], "integrated_rnr_path"
            )

    def test_load_and_convert_mirror_package(self):
        fixture = ROOT / "fixtures" / "synthetic-integrated-rnr-path.json"
        document = json.loads(fixture.read_text(encoding="utf-8"))
        node_ids = [value["id"] for value in document["graph"]["nodes"]]
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "package"
            package.mkdir()
            graph_zip = package / "test-evidence-graph.zip"
            with zipfile.ZipFile(graph_zip, "w") as archive:
                archive.writestr("graph.json", json.dumps(document))
            spec = {
                "schema_version": "1.0",
                "scenario_id": "test-integrated-package",
                "account_id": "111122223333",
                "region": "ap-northeast-2",
                "graph_node_ids": node_ids,
                "selected_runtime_path": {"frontend_task_id": "a" * 32},
                "steps": [{"step": 1, "title": "test"}],
            }
            (package / "test-mirror-spec.json").write_text(
                json.dumps(spec), encoding="utf-8"
            )
            input_path, loaded_spec, raw = MODULE.load_mirror_package(package)
            output = Path(temporary) / "generated"
            result = MODULE.convert(
                input_path,
                output,
                None,
                False,
                None,
                loaded_spec,
                str(package),
                raw,
            )
            self.assertEqual(result["generated_count"], 1)
            self.assertEqual(
                result["generated"][0]["scenario_id"], "test-integrated-package"
            )
            destination = Path(result["generated"][0]["directory"])
            self.assertTrue((destination / "source-mirror-spec.json").is_file())
            coverage = json.loads(
                (destination / "terraform-coverage.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(coverage["validation_steps"]), 1)


if __name__ == "__main__":
    unittest.main()
