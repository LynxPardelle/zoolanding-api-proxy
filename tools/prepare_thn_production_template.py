"""Prepare the standalone production auth discovery SAM template offline.

The shared API cannot enter this operation. Its existing stage, policies and
other tenants are deliberately outside the dedicated production resource set.
"""
from copy import deepcopy
import json
import sys
from pathlib import Path

def _project(value):
    if isinstance(value,dict): return {key:_project(item) for key,item in value.items()}
    if isinstance(value,list): return [_project(item) for item in value]
    if not isinstance(value,str): return value
    value=value.replace('zoolanding-content-hub-test-ServiceBindingRegistryV2','zoolanding-content-hub-prod-ServiceBindingRegistryV2').replace('SERVICE_BINDING#test#thn-journal-test-v2','SERVICE_BINDING#production#thn-journal-production-v2')
    if '-test-' in value or '#test#' in value or 'admin-test.' in value: raise ValueError('production_source_identity_unrecognized')
    return value

def prepare_template(source):
    if not isinstance(source,dict) or source.get('Transform')!='AWS::Serverless-2016-10-31' or set(source.get('Resources',{}))!={'ThnRuntimeApi','ThnAuthRuntimeV2Function','ThnRuntimeLogGroup'}:
        raise ValueError('production_source_resources_invalid')
    result=_project(deepcopy(source))
    # Object form is the current SAM schema; native REGIONAL configuration is unchanged.
    endpoint=result['Resources']['ThnRuntimeApi']['Properties']['EndpointConfiguration']
    if endpoint!='REGIONAL': raise ValueError('production_endpoint_source_invalid')
    result['Resources']['ThnRuntimeApi']['Properties']['EndpointConfiguration']={'Type':'REGIONAL'}
    props=result['Resources']['ThnAuthRuntimeV2Function']['Properties']
    if props.get('AutoPublishAlias')!='test' or props.get('Handler')!='thn_auth_runtime_v2.lambda_handler' or set(props.get('Events',{}))!={'RuntimeGet','RuntimePost'}:
        raise ValueError('production_function_source_invalid')
    props['AutoPublishAlias']='production'
    props['FunctionName']='zlp-thn-auth-runtime-production'
    props['Role']='arn:aws:iam::765932874577:role/zlp-thn-auth-runtime-prod-role'
    props.pop('Policies',None)
    props['Environment']['Variables']['THN_DEPLOYMENT_ENVIRONMENT']='production'
    result['Description']='Dedicated production The Hair Narrative auth runtime discovery.'
    result['Metadata']={'ThnProductionLifecycle':{'Profile':'production','StackName':'zoolanding-thn-auth-runtime-production','AutomaticActivation':False,'Prerequisites':'production registry and Cognito identifiers verified before review'}}
    result['Resources']['ThnRuntimeLogGroup']['DeletionPolicy']='Retain'
    result['Resources']['ThnRuntimeLogGroup']['UpdateReplacePolicy']='Retain'
    return result

def prepare_general_template(source):
    if not isinstance(source,dict) or source.get('Transform')!='AWS::Serverless-2016-10-31' or 'ApiProxyFunction' not in source.get('Resources',{}):
        raise ValueError('production_general_source_invalid')
    result=deepcopy(source)
    result['Parameters']['AuthRuntimeEnvironment']['Default']='prod'
    result['Parameters']['AuthRuntimeEnvironment']['AllowedValues']=['prod']
    result['Parameters']['EnableThnAuthRuntimeV2']['Default']='false'
    for logical,item in result['Resources'].items():
        if item['Type']=='AWS::Serverless::Function' and logical!='ThnAuthRuntimeV2Function':
            item.setdefault('Metadata',{})['BuildMethod']='makefile'
    result.setdefault('Metadata',{})['ThnProductionGeneralLifecycle']={'StackName':'zoolanding-api-proxy','DedicatedTHNRoutes':'excluded; EnableThnAuthRuntimeV2 must remain false','IncomingV1Changes':'full main source reviewed against native production baseline'}
    return result

def main(argv=None):
    import yaml
    args=sys.argv[1:] if argv is None else argv
    if len(args) not in {2,3}: raise ValueError('production_template_arguments_invalid')
    operation=prepare_general_template if len(args)==3 and args[2]=='general' else prepare_template
    if len(args)==3 and args[2]!='general': raise ValueError('production_template_scope_invalid')
    Path(args[1]).write_text(json.dumps(operation(yaml.safe_load(Path(args[0]).read_text(encoding='utf-8'))),sort_keys=True,indent=2)+'\n',encoding='utf-8')
    return 0
if __name__=='__main__': raise SystemExit(main())
