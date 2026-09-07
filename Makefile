.PHONY: build-ThnAuthRuntimeV2Function

build-ThnAuthRuntimeV2Function:
	python tools/build_thn_auth_runtime_v2_artifact.py "$(ARTIFACTS_DIR)"
