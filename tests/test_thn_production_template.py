from pathlib import Path
import unittest
import yaml
from tools.prepare_thn_production_template import prepare_template
ROOT=Path(__file__).resolve().parents[1]
class ProductionTemplateTests(unittest.TestCase):
    def test_standalone_production_registry_routes_and_alias_are_closed(self):
        source=yaml.safe_load((ROOT/'template-thn-runtime-test.yaml').read_text());result=prepare_template(source)
        props=result['Resources']['ThnAuthRuntimeV2Function']['Properties']
        self.assertEqual(props['AutoPublishAlias'],'production')
        self.assertEqual(props['FunctionName'],'zlp-thn-auth-runtime-production')
        self.assertEqual(props['Role'],'arn:aws:iam::765932874577:role/zlp-thn-auth-runtime-prod-role')
        self.assertNotIn('Policies',props)
        self.assertEqual(props['Environment']['Variables']['THN_DEPLOYMENT_ENVIRONMENT'],'production')
        self.assertEqual(props['Environment']['Variables']['SERVICE_BINDING_REGISTRY_V2_TABLE_NAME'],'zoolanding-content-hub-prod-ServiceBindingRegistryV2')
        self.assertEqual(set(props['Events']),{'RuntimeGet','RuntimePost'})
        self.assertNotIn('zoolanding-content-hub-test',yaml.safe_dump(result))
        expected_api=yaml.safe_load(yaml.safe_dump(source['Resources']['ThnRuntimeApi']))
        expected_api['Properties']['EndpointConfiguration']={'Type':'REGIONAL'}
        self.assertEqual(result['Resources']['ThnRuntimeApi'],expected_api)
    def test_cannot_transform_shared_api(self):
        with self.assertRaises(ValueError): prepare_template(yaml.safe_load((ROOT/'template.yaml').read_text()))
    def test_new_identity_cannot_silently_enter_the_profile(self):
        source=yaml.safe_load((ROOT/'template-thn-runtime-test.yaml').read_text());source['Resources']['ThnAuthRuntimeV2Function']['Properties']['Environment']['Variables']['BAD']='zoolanding-unknown-test-secret'
        with self.assertRaises(ValueError): prepare_template(source)

    def test_native_production_translation_has_only_closed_routes(self):
        import os
        from unittest.mock import patch
        from samtranslator.translator.transform import transform
        source=yaml.safe_load((ROOT/'template-thn-runtime-test.yaml').read_text());candidate=prepare_template(source)
        candidate['Resources']['ThnAuthRuntimeV2Function']['Properties']['CodeUri']={'Bucket':'synthetic-package','Key':'reviewed.zip','Version':'synthetic-version'}
        parameters=dict(DescriptorVersionId='synthetic-production-v1',DescriptorSha256='a'*64,AuthPolicyVersion='synthetic-production-v1',CognitoUserPoolId='us-east-1_synthetic',CognitoClientId='syntheticclient')
        with patch.dict(os.environ,{'AWS_DEFAULT_REGION':'us-east-1'}): native=transform(candidate,parameters,{})
        self.assertNotIn('Transform',native)
        self.assertEqual(set(native['Resources']['ThnRuntimeApi']['Properties']['Body']['paths']),{'/auth-v2/runtime-config'})
        self.assertIn('ThnAuthRuntimeV2FunctionAliasproduction',native['Resources'])
        self.assertNotIn('ThnAuthRuntimeV2FunctionRole',native['Resources'])
        self.assertEqual(native['Resources']['ThnAuthRuntimeV2Function']['Properties']['FunctionName'],'zlp-thn-auth-runtime-production')
        from tools import thn_production_release as release
        self.assertTrue(callable(getattr(release,'validate_dedicated_api_native',None)))
        release.validate_dedicated_api_native(native)
        unexpected=__import__('copy').deepcopy(native)
        unexpected['Resources']['ThnAuthRuntimeV2FunctionRole']={'Type':'AWS::IAM::Role'}
        with self.assertRaises(release.ReleaseError):release.validate_dedicated_api_native(unexpected)
    def test_general_projection_preserves_all_legacy_routes_and_build_targets(self):
        from tools.prepare_thn_production_template import prepare_general_template
        import copy
        source=yaml.safe_load((ROOT/'template.yaml').read_text());before=copy.deepcopy(source)
        result=prepare_general_template(source)
        self.assertEqual(source,before)
        self.assertEqual(result['Resources']['ApiProxyApi'],source['Resources']['ApiProxyApi'])
        self.assertEqual(result['Parameters']['AuthRuntimeEnvironment']['AllowedValues'],['prod'])
        self.assertEqual(result['Parameters']['EnableThnAuthRuntimeV2']['Default'],'false')
        makefile=(ROOT/'Makefile').read_text()
        for logical,item in result['Resources'].items():
            if item['Type']=='AWS::Serverless::Function':
                self.assertEqual(item['Metadata']['BuildMethod'],'makefile')
                self.assertIn('build-'+logical+':',makefile)

    def test_general_sealed_sources_exclude_local_servers_and_debug_tools(self):
        from tools.build_production_legacy_artifact import FILES
        self.assertEqual(set(FILES),{'auth_service.py','lambda_function.py','service_binding_registry_consumer_v2.py','thn_auth_runtime_v2.py','thn_current_user_provisioning_v2.py','thn_environment_profile.py','zoolanding_lambda_common.py'})

    def test_native_general_keeps_production_stage_and_legacy_handler_identities(self):
        from tools.prepare_thn_production_template import prepare_general_template
        from samtranslator.translator.transform import transform
        from unittest.mock import patch
        import os
        candidate=prepare_general_template(yaml.safe_load((ROOT/'template.yaml').read_text()))
        for item in candidate['Resources'].values():
            if item['Type']=='AWS::Serverless::Function':item['Properties']['CodeUri']={'Bucket':'synthetic','Key':'sealed.zip','Version':'v1'}
        parameters={name:item.get('Default','synthetic') for name,item in candidate['Parameters'].items()}
        for name,item in candidate['Parameters'].items():
            if item.get('Type')=='CommaDelimitedList':parameters[name]=parameters[name].split(',') if isinstance(parameters[name],str) else parameters[name]
        with patch.dict(os.environ,{'AWS_DEFAULT_REGION':'us-east-1'}):native=transform(candidate,parameters,{'AWSLambdaBasicExecutionRole':'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'})
        self.assertEqual(native['Resources']['ApiProxyApiProdStage']['Properties']['StageName'],'Prod')
        self.assertEqual(native['Resources']['AuthProvisioningExecutorFunction']['Properties']['Handler'],candidate['Resources']['AuthProvisioningExecutorFunction']['Properties']['Handler'])
    def test_general_builder_pins_lambda_linux_wheel_platform_not_host(self):
        import tempfile
        from unittest.mock import patch
        from tools import build_production_legacy_artifact as builder
        with tempfile.TemporaryDirectory() as directory,patch.object(builder.subprocess,'run') as run:
            builder.build(directory)
        command=run.call_args.args[0]
        for value in ('--only-binary=:all:','manylinux_2_34_x86_64','manylinux2014_x86_64','--implementation','cp','--python-version','313','--abi','cp313'):
            self.assertIn(value,command)

    def test_regional_endpoint_uses_object_shape_without_native_change(self):
        import copy, os
        from unittest.mock import patch
        from samtranslator.translator.transform import transform
        candidate=prepare_template(yaml.safe_load((ROOT/'template-thn-runtime-test.yaml').read_text()))
        self.assertEqual(candidate['Resources']['ThnRuntimeApi']['Properties']['EndpointConfiguration'], {'Type':'REGIONAL'})
        candidate['Resources']['ThnAuthRuntimeV2Function']['Properties']['CodeUri']={'Bucket':'synthetic-package','Key':'reviewed.zip','Version':'synthetic-version'}
        equivalent=copy.deepcopy(candidate)
        equivalent['Resources']['ThnRuntimeApi']['Properties']['EndpointConfiguration']='REGIONAL'
        parameters=dict(DescriptorVersionId='synthetic-production-v1',DescriptorSha256='a'*64,AuthPolicyVersion='synthetic-production-v1',CognitoUserPoolId='us-east-1_synthetic',CognitoClientId='syntheticclient')
        with patch.dict(os.environ,{'AWS_DEFAULT_REGION':'us-east-1'}):
            self.assertEqual(transform(candidate,parameters,{}),transform(equivalent,parameters,{}))
