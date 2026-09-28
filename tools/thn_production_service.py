"""Planned production names. They are not assertions of deployed/approved IAM.

Auth/Hub deploy roles match read-only GitHub production variables captured
2026-09-27. API/Image roles, CFN execution roles and private package bucket
require separately reviewed bootstrap and effective permission proof.
"""
from types import MappingProxyType
CONFIG=MappingProxyType({'service': 'api', 'generalStack': 'zoolanding-api-proxy', 'generalDeployRole': 'zoolanding-deployer-api-proxy-production-github-deploy', 'generalExecutionRole': 'zoolanding-deployer-api-proxy-production-cfn-exec', 'repository': 'zoolanding-api-proxy', 'stack': 'zoolanding-thn-auth-runtime-production', 'deployRole': 'zoolanding-deployer-thn-auth-runtime-production-github-deploy', 'executionRole': 'zoolanding-deployer-thn-auth-runtime-production-cfn-exec', 'sourceTemplate': 'template-thn-runtime-test.yaml', 'bucket': 'zlp-thn-production-releases-765932874577-us-east-1'})
