import ast
import copy
import os
import sys
import unittest


CURRENT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    import thn_current_user_provisioning_v2 as provisioning
except ModuleNotFoundError:
    provisioning = None


SCOPE = {
    "environment": "test",
    "domain": "thehairnarrative.com",
    "tenantId": "thehairnarrative-com",
    "hubId": "thehairnarrative-com-journal",
    "authProfileId": "journal-owner",
    "serviceBindingId": "thn-journal-test-v2",
}
SUBJECT = "1d52c2fe-2a70-4ec0-b85e-07e8fc0ecda4"


def provision_request(*, account_purpose="client-owner", subject=SUBJECT):
    return {
        "contractVersion": 1,
        "scope": copy.deepcopy(SCOPE),
        "subject": subject,
        "accountPurpose": account_purpose,
    }


def current_user(
    *,
    account_purpose="client-owner",
    subject=SUBJECT,
    session_version=4,
    enabled=True,
):
    return {
        **provision_request(account_purpose=account_purpose, subject=subject),
        "sessionVersion": session_version,
        "enabled": enabled,
    }


def disable_request(
    *,
    account_purpose="client-owner",
    subject=SUBJECT,
    expected_session_version=4,
):
    return {
        **provision_request(account_purpose=account_purpose, subject=subject),
        "expectedSessionVersion": expected_session_version,
    }


class TestCurrentUserProvisioningV2Availability(unittest.TestCase):
    def test_module_exists_but_shared_v1_handlers_do_not_wire_it(self):
        self.assertIsNotNone(provisioning)
        self.assertTrue(callable(getattr(provisioning, "provision_current_user", None)))
        self.assertTrue(callable(getattr(provisioning, "disable_current_user", None)))

        forbidden_names = {
            "thn_current_user_provisioning_v2",
            "provision_current_user",
            "disable_current_user",
        }
        for filename in ("auth_service.py", "lambda_function.py"):
            with self.subTest(filename=filename):
                path = os.path.join(PROJECT_ROOT, filename)
                with open(path, encoding="utf-8") as source_file:
                    tree = ast.parse(source_file.read(), filename=path)
                imported_modules = {
                    alias.name
                    for node in ast.walk(tree)
                    if isinstance(node, ast.Import)
                    for alias in node.names
                }
                imported_from_modules = {
                    node.module
                    for node in ast.walk(tree)
                    if isinstance(node, ast.ImportFrom)
                }
                referenced_names = {
                    node.id for node in ast.walk(tree) if isinstance(node, ast.Name)
                }
                referenced_attributes = {
                    node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
                }
                self.assertTrue(forbidden_names.isdisjoint(imported_modules))
                self.assertTrue(forbidden_names.isdisjoint(imported_from_modules))
                self.assertTrue(forbidden_names.isdisjoint(referenced_names))
                self.assertTrue(forbidden_names.isdisjoint(referenced_attributes))


@unittest.skipUnless(
    provisioning is not None
    and callable(getattr(provisioning, "provision_current_user", None))
    and callable(getattr(provisioning, "disable_current_user", None)),
    "THN current-user provisioning v2 implementation is not available yet",
)
class TestCurrentUserProvisioningV2(unittest.TestCase):
    def assert_invalid(self, callback):
        with self.assertRaises(provisioning.CurrentUserProvisioningError) as caught:
            callback()
        self.assertEqual(str(caught.exception), "current user provisioning request is invalid")

    def test_provision_assigns_purpose_once_with_disabled_version_one_state(self):
        for purpose in ("qa", "client-owner"):
            request = provision_request(account_purpose=purpose)
            original = copy.deepcopy(request)

            result = provisioning.provision_current_user(request)

            self.assertEqual(
                result,
                {
                    **original,
                    "sessionVersion": 1,
                    "enabled": False,
                },
            )
            self.assertEqual(request, original)
            result["scope"]["domain"] = "mutated.example"
            self.assertEqual(request, original)

    def test_provision_rejects_any_existing_state_instead_of_reassigning_purpose(self):
        for existing in ({}, current_user(), current_user(account_purpose="qa")):
            with self.subTest(existing=existing):
                self.assert_invalid(
                    lambda existing=existing: provisioning.provision_current_user(
                        provision_request(),
                        existing_user=existing,
                    )
                )

    def test_provision_rejects_missing_unknown_or_invalid_request_fields(self):
        cases = []
        missing = provision_request()
        missing.pop("subject")
        cases.append(missing)
        unknown = provision_request()
        unknown["enabled"] = True
        cases.append(unknown)
        cases.extend(
            [
                {**provision_request(), "contractVersion": True},
                {**provision_request(), "contractVersion": 2},
                {**provision_request(), "accountPurpose": "owner"},
                {**provision_request(), "accountPurpose": "QA"},
                {**provision_request(), "subject": ""},
                {**provision_request(), "subject": "contains whitespace"},
                {**provision_request(), "subject": 123},
            ]
        )
        for request in cases:
            with self.subTest(request=request):
                self.assert_invalid(lambda request=request: provisioning.provision_current_user(request))

    def test_provision_rejects_every_scope_drift_and_scope_shape_change(self):
        replacements = {
            "environment": "prod",
            "domain": "other.example",
            "tenantId": "other-tenant",
            "hubId": "other-hub",
            "authProfileId": "other-profile",
            "serviceBindingId": "other-binding",
        }
        cases = []
        for field, replacement in replacements.items():
            request = provision_request()
            request["scope"][field] = replacement
            cases.append(request)
        missing = provision_request()
        missing["scope"].pop("hubId")
        cases.append(missing)
        unknown = provision_request()
        unknown["scope"]["writerMode"] = "client-owner"
        cases.append(unknown)
        cases.extend([{**provision_request(), "scope": None}, {**provision_request(), "scope": []}])

        for request in cases:
            with self.subTest(request=request):
                self.assert_invalid(lambda request=request: provisioning.provision_current_user(request))

    def test_disable_preserves_purpose_and_scope_and_bumps_session_version(self):
        for purpose in ("qa", "client-owner"):
            state = current_user(account_purpose=purpose, session_version=7, enabled=True)
            request = disable_request(
                account_purpose=purpose,
                expected_session_version=7,
            )
            original_state = copy.deepcopy(state)
            original_request = copy.deepcopy(request)

            result = provisioning.disable_current_user(request, current_user=state)

            self.assertEqual(
                result,
                {
                    **original_state,
                    "sessionVersion": 8,
                    "enabled": False,
                },
            )
            self.assertEqual(state, original_state)
            self.assertEqual(request, original_request)
            result["scope"]["tenantId"] = "mutated"
            self.assertEqual(state, original_state)

    def test_disable_uses_compare_and_swap_and_rejects_purpose_or_identity_change(self):
        state = current_user(account_purpose="client-owner", session_version=5)
        cases = (
            disable_request(account_purpose="qa", expected_session_version=5),
            disable_request(subject="different-subject", expected_session_version=5),
            disable_request(expected_session_version=4),
            disable_request(expected_session_version=6),
        )
        for request in cases:
            with self.subTest(request=request):
                self.assert_invalid(
                    lambda request=request: provisioning.disable_current_user(
                        request,
                        current_user=state,
                    )
                )

    def test_disable_rejects_invalid_versions_fields_and_current_state(self):
        state = current_user(session_version=3)
        requests = []
        missing = disable_request(expected_session_version=3)
        missing.pop("expectedSessionVersion")
        requests.append(missing)
        unknown = disable_request(expected_session_version=3)
        unknown["reason"] = "requested"
        requests.append(unknown)
        requests.extend(
            disable_request(expected_session_version=value)
            for value in (True, False, 0, -1, "3", 3.0)
        )
        for request in requests:
            with self.subTest(request=request):
                self.assert_invalid(
                    lambda request=request: provisioning.disable_current_user(
                        request,
                        current_user=state,
                    )
                )

        states = []
        missing_state = current_user(session_version=3)
        missing_state.pop("enabled")
        states.append(missing_state)
        unknown_state = current_user(session_version=3)
        unknown_state["group"] = "Owners"
        states.append(unknown_state)
        states.extend(current_user(session_version=value) for value in (True, 0, -1, "3", 3.0))
        states.extend(current_user(enabled=value) for value in (0, 1, "false", None))
        states.append(None)
        for candidate in states:
            with self.subTest(candidate=candidate):
                self.assert_invalid(
                    lambda candidate=candidate: provisioning.disable_current_user(
                        disable_request(expected_session_version=3),
                        current_user=candidate,
                    )
                )

    def test_module_is_a_pure_contract_without_provider_or_storage_calls(self):
        path = os.path.join(PROJECT_ROOT, "thn_current_user_provisioning_v2.py")
        with open(path, encoding="utf-8") as source_file:
            tree = ast.parse(source_file.read(), filename=path)

        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        self.assertTrue({"boto3", "botocore"}.isdisjoint(imported_roots))

        forbidden_calls = {
            "put_item",
            "update_item",
            "delete_item",
            "transact_write_items",
            "admin_create_user",
            "admin_update_user_attributes",
            "admin_disable_user",
        }
        called_attributes = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(forbidden_calls.isdisjoint(called_attributes))


if __name__ == "__main__":
    unittest.main()
