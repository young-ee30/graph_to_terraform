import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
