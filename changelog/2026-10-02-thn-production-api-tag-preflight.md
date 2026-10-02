# Private THN production API tag permission preflight

The protected release now requires a separate, exact IAM simulation request for the URL-encoded API Gateway REST API and stage tag path. For private API activation it checks the request in the initial preflight, before S3 upload or CloudFormation change-set creation. The later native review checks the live REST API and Stage provider schemas and repeats the permission proof against the actual change set.

The previous plan covered `/restapis/*` but omitted `/tags/arn%3Aaws%3Aapigateway%3Aus-east-1%3A%3A%2Frestapis%2F*`. That omission allowed the review to pass and made CloudFormation fail while creating the API. The regression test reproduces the old-plan rejection and accepts only the separate exact tag request. No AWS release is initiated by this source change.
