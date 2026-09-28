.PHONY: build-ThnAuthRuntimeV2Function

build-ThnAuthRuntimeV2Function:
	python tools/build_thn_auth_runtime_v2_artifact.py "$(ARTIFACTS_DIR)"

build-ApiProxyFunction:
	python tools/build_production_legacy_artifact.py "$(ARTIFACTS_DIR)"

build-AuthProvisioningExecutorFunction:
	python tools/build_production_legacy_artifact.py "$(ARTIFACTS_DIR)"

build-AuthJwtAuthorizerFunction:
	python tools/build_production_legacy_artifact.py "$(ARTIFACTS_DIR)"
