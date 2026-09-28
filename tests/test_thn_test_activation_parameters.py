"""Isolated TEST selection must never override shared API Proxy parameters."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

from tools import prepare_test_parameters as subject

BASE = {"AUTH_PROVISIONING_ALLOWED_ROLE_ARNS": "arn:aws:iam::123456789012:role/example-test-operator"}
ROLE = "arn:aws:iam::123456789012:role/example-test-deploy"
V2 = {
    "EnableThnAuthRuntimeV2": "true",
    "ThnAuthRuntimeV2DescriptorVersionId": "reviewed-version-1",
    "ThnAuthRuntimeV2DescriptorSha256": "a" * 64,
    "ThnAuthRuntimeV2AuthPolicyVersion": "reviewed-policy-1",
    "ThnAuthRuntimeV2CognitoUserPoolId": "us-east-1_example123",
    "ThnAuthRuntimeV2CognitoClientId": "exampleclient123",
}


def environment(parameters=None, **overrides):
    envelope = {"schemaVersion": 1, "environment": "test", "parameters": copy.deepcopy(V2 if parameters is None else parameters)}
    envelope.update(overrides)
    return {**BASE, "AWS_ROLE_ARN": ROLE, "THN_V2_TEST_PARAMETERS_JSON": json.dumps(envelope)}


class ThnTestSelectionTests(unittest.TestCase):
    def test_complete_selection_is_applied_without_v1_change(self):
        actual, sensitive = subject.build_parameters(environment())
        default, default_sensitive = subject.build_parameters(BASE)
        self.assertEqual({key: actual[key] for key in V2}, V2)
        self.assertEqual({key: value for key, value in actual.items() if key not in V2},
                         {key: value for key, value in default.items() if key not in V2})
        self.assertEqual(sensitive, default_sensitive)
        self.assertEqual(actual["AuthProvisioningApplyEnabled"], "false")

    def test_omission_is_disabled(self):
        actual, _ = subject.build_parameters(BASE)
        self.assertEqual(actual["EnableThnAuthRuntimeV2"], "false")

    def test_envelope_is_closed_and_test_only(self):
        for overrides in ({"environment": "prod"}, {"schemaVersion": True}, {"schemaVersion": 2},
                          {"writerMode": "client-owner"}, {"parameters": []}):
            with self.subTest(overrides=overrides), self.assertRaises(subject.ParameterPreparationError):
                subject.build_parameters(environment(**overrides))

    def test_partial_and_shared_parameters_are_rejected(self):
        partial = dict(V2)
        partial.pop("ThnAuthRuntimeV2DescriptorSha256")
        for values in (partial, {**V2, "AuthProvisioningApplyEnabled": "true"},
                       {**V2, "ConfigTableName": "another-table"}, {**V2, "writerEpoch": "4"}):
            with self.subTest(keys=sorted(values)), self.assertRaises(subject.ParameterPreparationError):
                subject.build_parameters(environment(values))

    def test_activation_rejects_placeholder_and_invalid_identifiers(self):
        for field, value in (
            ("EnableThnAuthRuntimeV2", True),
            ("ThnAuthRuntimeV2DescriptorVersionId", "BLOCKED"),
            ("ThnAuthRuntimeV2DescriptorSha256", "0" * 64),
            ("ThnAuthRuntimeV2AuthPolicyVersion", "BLOCKED"),
            ("ThnAuthRuntimeV2CognitoUserPoolId", "BLOCKED"),
            ("ThnAuthRuntimeV2CognitoUserPoolId", "us-west-2_example"),
            ("ThnAuthRuntimeV2CognitoClientId", "BLOCKED"),
            ("ThnAuthRuntimeV2CognitoClientId", "https://example.test"),
        ):
            with self.subTest(field=field), self.assertRaises(subject.ParameterPreparationError):
                subject.build_parameters(environment({**V2, field: value}))

    def test_invalid_and_duplicate_json_are_not_echoed(self):
        for raw in ("not-json-sentinel", "[]", " " * 17000,
                    '{"schemaVersion":1,"environment":"test","parameters":{},"parameters":{}}',
                    "[" * 1500 + "0" + "]" * 1500):
            with self.subTest(length=len(raw)):
                with self.assertRaises(subject.ParameterPreparationError) as error:
                    subject.build_parameters({**BASE, "AWS_ROLE_ARN": ROLE, "THN_V2_TEST_PARAMETERS_JSON": raw})
                self.assertNotIn(raw, str(error.exception))

    def test_supplied_selection_requires_deployment_identity(self):
        for role in ("", "not-an-arn", "arn:aws:iam::123456789012:user/example"):
            with self.subTest(role=role), self.assertRaises(subject.ParameterPreparationError):
                subject.build_parameters({**environment(), "AWS_ROLE_ARN": role})



class ThnCloudPreflightTests(unittest.TestCase):
    def test_selection_contract_is_reported_without_cloud_or_parameter_files(self):
        with mock.patch.dict("os.environ", {}, clear=True), \
                mock.patch("sys.argv", ["prepare_test_parameters.py", "--thn-selection-contract"]), \
                mock.patch("builtins.print") as output, \
                mock.patch.object(subject, "verify_cloud_guards", side_effect=AssertionError("No cloud")), \
                mock.patch.object(subject, "build_parameters", side_effect=AssertionError("No files")):
            self.assertEqual(subject.main(), 0)
            output.assert_called_once_with("thn-test-selection/v1")

    def test_cloud_cli_mode_does_not_prepare_or_write_parameters(self):
        with mock.patch.dict("os.environ", environment(), clear=True), \
                mock.patch("sys.argv", ["prepare_test_parameters.py", "--verify-cloud-guards"]), \
                mock.patch.object(subject, "verify_cloud_guards", create=True) as guard, \
                mock.patch.object(subject, "build_parameters", side_effect=AssertionError("Preflight must not prepare files")):
            self.assertEqual(subject.main(), 0)
            guard.assert_called_once()

    def test_unknown_cli_arguments_are_rejected_before_preparation(self):
        with mock.patch("sys.argv", ["prepare_test_parameters.py", "--activate"]), \
                mock.patch.object(subject, "build_parameters", side_effect=AssertionError("Unknown CLI must not prepare files")):
            with self.assertRaises(subject.ParameterPreparationError):
                subject.main()

    def invoke_guard(self, env, runner):
        guard = getattr(subject, "verify_cloud_guards", None)
        self.assertTrue(callable(guard), "The reviewed TEST cloud preflight is missing")
        return guard(env, runner=runner)

    def replies(self):
        return [
            {"Account": "123456789012"},
            [["zoolanding-auth-admin-test", "UPDATE_COMPLETE", True]],
            [
                {"logicalId": "ThnAuthAdminV2UserPool", "id": V2["ThnAuthRuntimeV2CognitoUserPoolId"], "type": "AWS::Cognito::UserPool", "status": "CREATE_COMPLETE"},
                {"logicalId": "ThnAuthAdminV2UserPoolClient", "id": V2["ThnAuthRuntimeV2CognitoClientId"], "type": "AWS::Cognito::UserPoolClient", "status": "CREATE_COMPLETE"},
            ],
            ["AWS::DynamoDB::Table", "zoolanding-content-hub-test-ServiceBindingRegistryV2", "CREATE_COMPLETE"],
        ]

    def runner(self, replies):
        return mock.Mock(side_effect=[subprocess.CompletedProcess([], 0, json.dumps(value), "") for value in replies])

    def test_omitted_selection_makes_no_cloud_requests(self):
        runner = mock.Mock()
        self.invoke_guard(BASE, runner)
        runner.assert_not_called()

    def test_wrong_region_is_rejected_before_cloud(self):
        for key in ("AWS_REGION", "AWS_DEFAULT_REGION"):
            runner = mock.Mock()
            with self.subTest(key=key), self.assertRaises(subject.ParameterPreparationError):
                self.invoke_guard({**environment(), key: "us-west-2"}, runner)
            runner.assert_not_called()

    def test_verified_read_only_preflight(self):
        runner = self.runner(self.replies())
        self.invoke_guard(environment(), runner)
        self.assertEqual(runner.call_count, 4)
        for call in runner.call_args_list:
            args = call.args[0]
            self.assertEqual(args[0], "aws")
            self.assertIn(args[2], {"get-caller-identity", "describe-stacks", "list-stack-resources", "describe-stack-resource"})
            self.assertIn("--query", args)
            self.assertIn("--no-cli-pager", args)
            self.assertEqual(args[args.index("--region") + 1], "us-east-1")
            self.assertFalse(call.kwargs.get("shell", False))
            self.assertEqual(call.kwargs["timeout"], 30)

    def test_identity_state_and_resource_mismatches_fail_closed(self):
        for index, replacement in (
            (0, {"Account": "999999999999"}),
            (1, [["zoolanding-auth-admin-test", "UPDATE_COMPLETE", False]]),
            (1, [["zoolanding-auth-admin-production", "UPDATE_COMPLETE", True]]),
            (1, [["zoolanding-auth-admin-test", "UPDATE_IN_PROGRESS", True]]),
            (2, []),
            (2, [{"logicalId": "ThnAuthAdminV2UserPool", "id": "us-east-1_wrong", "type": "AWS::Cognito::UserPool", "status": "CREATE_COMPLETE"}]),
            (3, ["AWS::DynamoDB::Table", "another-registry", "CREATE_COMPLETE"]),
        ):
            replies = self.replies()
            replies[index] = replacement
            with self.subTest(index=index, replacement=replacement), self.assertRaises(subject.ParameterPreparationError):
                self.invoke_guard(environment(), self.runner(replies))

    def test_cloud_failures_return_only_a_safe_error(self):
        for outcome in (
            subprocess.CompletedProcess([], 1, "", "private-cloud-error-sentinel"),
            subprocess.CompletedProcess([], 0, "not-json-sentinel", ""),
            subprocess.CompletedProcess([], 0, " " * 17000, ""),
            subprocess.TimeoutExpired(["aws"], 30),
        ):
            runner = mock.Mock(side_effect=outcome if isinstance(outcome, Exception) else None,
                               return_value=outcome)
            with self.subTest(kind=type(outcome).__name__):
                with self.assertRaises(subject.ParameterPreparationError) as error:
                    self.invoke_guard(environment(), runner)
                self.assertEqual(str(error.exception), "thn_test_cloud_guard_failed")

    def test_disabled_runtime_does_not_require_runtime_dependencies(self):
        wanted = {**V2, "EnableThnAuthRuntimeV2": "false"}
        runner = self.runner([{"Account": "123456789012"}])
        self.invoke_guard(environment(wanted), runner)
        self.assertEqual(runner.call_count, 1)


class ThnWorkflowSelectionTests(unittest.TestCase):
    def test_both_workflows_forward_selection_and_check_before_changes(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("deploy-test.yml", "rollback-test.yml"):
            workflow = (root / ".github" / "workflows" / name).read_text()
            with self.subTest(name=name):
                self.assertEqual(workflow.count("THN_V2_TEST_PARAMETERS_JSON: ${{ vars.THN_V2_TEST_PARAMETERS_JSON }}"), 2)
                self.assertIn("prepare_test_parameters.py --verify-cloud-guards", workflow)
                self.assertIn("if: ${{ vars.THN_V2_TEST_PARAMETERS_JSON != '' }}", workflow)
                self.assertIn('if [ -n "${THN_V2_TEST_PARAMETERS_JSON:-}" ]; then', workflow)
                self.assertIn('"thn-test-selection/v1"', workflow)
                self.assertIn('thn_test_selection_contract_missing', workflow)
                self.assertLess(workflow.index("prepare_test_parameters.py --thn-selection-contract"),
                                workflow.index("uses: aws-actions/configure-aws-credentials@"))
                self.assertLess(workflow.index("uses: aws-actions/configure-aws-credentials@"),
                                workflow.index("prepare_test_parameters.py --verify-cloud-guards"))
                self.assertLess(workflow.index("prepare_test_parameters.py --verify-cloud-guards"),
                                workflow.index("run: bash .aws-sam/build/release-tools/run_test_change_set.sh"))


if __name__ == "__main__":
    unittest.main()
