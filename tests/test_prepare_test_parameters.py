import unittest
import re
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools.prepare_test_parameters import ParameterPreparationError, build_parameters

class PrepareTestParametersTests(unittest.TestCase):
    def test_requires_operator_allowlist(self):
        with self.assertRaises(ParameterPreparationError):
            build_parameters({})

    def test_keeps_thn_runtime_disabled(self):
        parameters, sensitive = build_parameters({"AUTH_PROVISIONING_ALLOWED_ROLE_ARNS": "arn:aws:iam::123456789012:role/test"})
        self.assertEqual(parameters["AuthRuntimeEnvironment"], "test")
        self.assertEqual(parameters["AuthProvisioningStateTableMode"], "existing")
        self.assertEqual(parameters["EnableThnAuthRuntimeV2"], "false")
        self.assertEqual(sensitive, set())
        template = (Path(__file__).resolve().parents[1] / "template.yaml").read_text(encoding="utf-8")
        declared = set(re.findall(r"(?m)^  ([A-Za-z][A-Za-z0-9]+):$", template.split("\nRules:", 1)[0]))
        self.assertEqual(set(parameters), declared)

if __name__ == "__main__":
    unittest.main()
