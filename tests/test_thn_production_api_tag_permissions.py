"""Regression for CloudFormation's API Gateway tag-on-create ARN."""
import json
import os
import unittest
from unittest.mock import Mock, patch

from tools import run_thn_production_release as driver
from tools.thn_production_release import ReleaseError


class ApiGatewayTagPermissionTests(unittest.TestCase):
    def test_native_review_requires_encoded_tag_resource_not_only_rest_api_paths(self):
        account = '765932874577'
        caller = f"arn:aws:iam::{account}:role/{driver.CONFIG['deployRole']}"
        execution = f"arn:aws:iam::{account}:role/{driver.CONFIG['executionRole']}"
        source = {'sourceSha': 'a' * 40}
        trust = {'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRoleWithWebIdentity',
            'Principal': {'Federated': f'arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com'},
            'Condition': {'StringEquals': {
                'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
                'token.actions.githubusercontent.com:sub':
                    f"repo:LynxPardelle/{driver.CONFIG['repository']}:environment:production"}}}]}
        roles = {
            driver.CONFIG['deployRole']: {'Arn': caller, 'AssumeRolePolicyDocument': trust},
            driver.CONFIG['executionRole']: {'Arn': execution, 'AssumeRolePolicyDocument':
                {'Statement': [{'Effect': 'Allow', 'Action': 'sts:AssumeRole',
                    'Principal': {'Service': 'cloudformation.amazonaws.com'}}]}},
        }
        iam = Mock()
        iam.get_role.side_effect = lambda **kw: {'Role': roles[kw['RoleName']]}
        iam.get_paginator.return_value.paginate.return_value = []
        iam.simulate_principal_policy.side_effect = lambda **kw: {'EvaluationResults': [
            {'EvalActionName': action, 'EvalDecision': 'allowed', 'ResourceSpecificResults': [
                {'EvalResourceName': resource, 'EvalResourceDecision': 'allowed'}
                for resource in kw['ResourceArns']]} for action in kw['ActionNames']]}
        schema = {'tagging': {'taggable': True, 'tagOnCreate': True,
            'permissions': ['apigateway:PUT', 'apigateway:GET', 'apigateway:DELETE']},
            'handlers': {'read': {'permissions': ['apigateway:GET']},
                'create': {'permissions': ['apigateway:POST', 'apigateway:PUT']},
                'delete': {'permissions': ['apigateway:DELETE']}}}
        cf = Mock()
        cf.describe_type.return_value = {'Schema': json.dumps(schema)}
        sts = Mock()
        sts.get_caller_identity.return_value = {'Account': account,
            'Arn': f"arn:aws:sts::{account}:assumed-role/{driver.CONFIG['deployRole']}/run"}
        session = Mock(region_name='us-east-1')
        session.client.side_effect = lambda name: {'iam': iam, 'cloudformation': cf, 'sts': sts}[name]
        base = [
            {'principalArn': caller, 'actions': sorted(driver.CALLER_ACTIONS | {
                'cognito-idp:DescribeUserPool','cognito-idp:GetUserPoolMfaConfig','dynamodb:GetItem'}),
                'resources': ['*'], 'context': []},
            {'principalArn': execution,
             'actions': ['apigateway:GET', 'apigateway:POST', 'apigateway:PUT', 'apigateway:DELETE'],
             'resources': ['arn:aws:apigateway:us-east-1::/restapis',
                           'arn:aws:apigateway:us-east-1::/restapis/*'],
             'context': [{'ContextKeyName': 'aws:RequestedRegion',
                          'ContextKeyValues': ['us-east-1'], 'ContextKeyType': 'string'}]},
        ]
        plan = {'schemaVersion': 1, 'environment': 'production',
            'service': driver.CONFIG['service'], 'purpose': 'state',
            'sourceSha': source['sourceSha'], 'requests': base}
        change = [{'ResourceChange': {'Action': 'Add', 'LogicalResourceId': 'ThnRuntimeApi',
            'ResourceType': 'AWS::ApiGateway::RestApi'}}]
        template = {'Resources': {'ThnRuntimeApi': {'Properties': {'Body': {'openapi': '3.0.1'}}}}}

        with patch.dict(os.environ, {'THN_PRODUCTION_PERMISSION_PLAN_JSON': json.dumps(plan)}):
            with self.assertRaisesRegex(ReleaseError, 'production_api_tag_permission_coverage_incomplete'):
                driver.identity_and_permissions(session, source, 'state', change, template)
        iam.simulate_principal_policy.assert_not_called()

        # The old plan must also fail in the initial preflight, before review
        # uploads S3 objects or asks CloudFormation to create a change set.
        activate = {**plan, 'purpose': 'activate'}
        with patch.dict(os.environ, {'THN_PRODUCTION_PERMISSION_PLAN_JSON': json.dumps(activate)}):
            with self.assertRaisesRegex(ReleaseError, 'production_api_tag_permission_coverage_incomplete'):
                driver.identity_and_permissions(session, source, 'activate')
        iam.simulate_principal_policy.assert_not_called()

        tag = {'principalArn': execution,
            'actions': ['apigateway:GET', 'apigateway:PUT', 'apigateway:DELETE'],
            'resources': ['arn:aws:apigateway:us-east-1::/tags/arn%3Aaws%3Aapigateway%3Aus-east-1%3A%3A%2Frestapis%2F*'],
            'context': [{'ContextKeyName': 'aws:RequestedRegion',
                         'ContextKeyValues': ['us-east-1'], 'ContextKeyType': 'string'}]}
        with patch.dict(os.environ, {'THN_PRODUCTION_PERMISSION_PLAN_JSON': json.dumps({**plan, 'requests': [*base, tag]})}):
            driver.identity_and_permissions(session, source, 'state', change, template)
        self.assertEqual(iam.simulate_principal_policy.call_count, 3)
        self.assertEqual(iam.simulate_principal_policy.call_args_list[-1].kwargs['ResourceArns'], tag['resources'])
        with patch.dict(os.environ, {'THN_PRODUCTION_PERMISSION_PLAN_JSON': json.dumps({**activate, 'requests': [*base, tag]})}):
            driver.identity_and_permissions(session, source, 'activate')
        self.assertEqual(iam.simulate_principal_policy.call_count, 6)
        for mutation in (
            {**tag, 'resources': ['arn:aws:apigateway:us-east-1::/tags/*']},
            {**tag, 'actions': ['apigateway:PUT']},
            {**tag, 'context': []},
        ):
            with self.subTest(mutation=mutation), patch.dict(os.environ, {
                    'THN_PRODUCTION_PERMISSION_PLAN_JSON': json.dumps({**plan, 'requests': [*base, mutation]})}):
                with self.assertRaisesRegex(ReleaseError, 'production_api_tag_permission_coverage_incomplete'):
                    driver.identity_and_permissions(session, source, 'state', change, template)
        cf.describe_type.return_value = {'Schema': json.dumps({**schema, 'tagging': {'taggable': True,
            'tagOnCreate': False, 'permissions': schema['tagging']['permissions']}})}
        with patch.dict(os.environ, {'THN_PRODUCTION_PERMISSION_PLAN_JSON': json.dumps({**plan, 'requests': [*base, tag]})}):
            with self.assertRaisesRegex(ReleaseError, 'production_api_tag_schema_invalid'):
                driver.identity_and_permissions(session, source, 'state', change, template)


if __name__ == '__main__':
    unittest.main()
