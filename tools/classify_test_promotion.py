"""Credential-free, fail-closed selection of one reviewed TEST source promotion."""
import json
import os
import re
import sys

FIELDS = {"schemaVersion", "mode", "devSha", "devTree", "testBaseSha"}


class PromotionSelectionError(ValueError):
    """Diagnostics contain no supplied values."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PromotionSelectionError("promotion_selection_invalid")
        result[key] = value
    return result


def _git_object(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{40}", value) and value != "0" * 40


def classify_selection(raw, dev_sha, dev_tree, test_base_sha):
    if not all(_git_object(value) for value in (dev_sha, dev_tree, test_base_sha)):
        raise PromotionSelectionError("promotion_context_invalid")
    if raw is None or raw == "":
        return "legacy"
    try:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 4096:
            raise ValueError()
        value = json.loads(raw, object_pairs_hook=_object)
    except (ValueError, UnicodeError, RecursionError):
        raise PromotionSelectionError("promotion_selection_invalid") from None
    if (not isinstance(value, dict) or set(value) != FIELDS
            or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["mode"] != "thn-source-only"
            or not all(_git_object(value[key]) for key in ("devSha", "devTree", "testBaseSha"))):
        raise PromotionSelectionError("promotion_selection_invalid")
    if (value["devSha"], value["devTree"], value["testBaseSha"]) != (dev_sha, dev_tree, test_base_sha):
        raise PromotionSelectionError("promotion_selection_stale")
    return "thn-source-only"


def main(argv=None):
    try:
        if (sys.argv[1:] if argv is None else argv):
            raise PromotionSelectionError("promotion_arguments_invalid")
        mode = classify_selection(os.environ.get("API_TEST_PROMOTION_SELECTION_JSON"),
                                  os.environ.get("PROMOTED_DEV_SHA"), os.environ.get("PROMOTED_DEV_TREE"),
                                  os.environ.get("PROMOTED_TEST_BASE_SHA"))
    except PromotionSelectionError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
