import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
class ClosedEnvironmentProfileTests(unittest.TestCase):
    def run_profile(self, environment, expression):
        env = dict(os.environ)
        if environment is None:
            env.pop("THN_DEPLOYMENT_ENVIRONMENT", None)
        else:
            env["THN_DEPLOYMENT_ENVIRONMENT"] = environment
        return subprocess.run([sys.executable, "-c", expression], cwd=ROOT, env=env, text=True, capture_output=True)

    def test_test_contract_is_unchanged(self):
        result = self.run_profile(None, "import thn_environment_profile as p; print(p.PROFILE['environment'], p.PROFILE['cookieNamespace'], p.PROFILE['adminHost'])")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "test endefiz7dkk635k6di6k admin-test.thehairnarrative.com")

    def test_production_has_distinct_closed_coordinates(self):
        result = self.run_profile("production", "import thn_environment_profile as p; print(p.PROFILE['environment'], p.PROFILE['samEnvironment'], p.PROFILE['cookieNamespace'], p.PROFILE['registryPartitionKey'], p.PROFILE['authStack'])")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "production prod ltnafwb6videyraictgp SERVICE_BINDING#production#thn-journal-production-v2 zoolanding-auth-admin-prod")

    def test_aliases_and_unknown_environment_fail_closed(self):
        for environment in ("prod", "dev", "Production", "", " production", "test "):
            with self.subTest(environment=environment):
                self.assertNotEqual(self.run_profile(environment, "import thn_environment_profile").returncode, 0)

    def test_profile_is_immutable(self):
        self.assertNotEqual(self.run_profile("production", "from thn_environment_profile import PROFILE; PROFILE['environment']='test'").returncode, 0)

    def test_runtime_coordinates_are_sealed_at_import(self):
        code = "import os; from thn_environment_profile import PROFILE; os.environ['THN_DEPLOYMENT_ENVIRONMENT']='test'; assert PROFILE['environment']=='production'"
        result = self.run_profile("production", code)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runtime_rejects_test_origin_under_production_profile(self):
        code = "import thn_auth_runtime_v2 as r; assert r.ADMIN_ORIGIN=='https://admin.thehairnarrative.com'; event={'headers':{'origin':'https://admin-test.thehairnarrative.com','x-forwarded-host':'admin-test.thehairnarrative.com'}}; response=r.lambda_handler(event,None); assert response['statusCode']==403; assert 'Access-Control-Allow-Origin' not in response['headers']"
        result=self.run_profile('production',code)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_production_runtime_binding_and_registry_match(self):
        code = "import service_binding_registry_consumer_v2 as c; assert c.APPROVED_TABLE_NAME=='zoolanding-content-hub-prod-ServiceBindingRegistryV2'; assert c.APPROVED_ENVIRONMENT=='production'; assert c.BINDING_DESCRIPTOR['serviceBindingId']=='thn-journal-production-v2'; assert c.APPROVED_COOKIE_NAMESPACE=='ltnafwb6videyraictgp'; assert 'qa-only' not in c.ALLOWED_WRITER_MODES; assert c.RESOURCE_BINDING_RESOURCES['authoringFunctionArn'][1]=='function:zoolanding-content-hub-prod-ThnContentHubV2Authoring'"
        result=self.run_profile('production',code)
        self.assertEqual(result.returncode,0,result.stderr)
