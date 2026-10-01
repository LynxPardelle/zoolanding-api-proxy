# Dedicated THN production API runtime role: local release repair

The production SAM projection now uses the exact `zlp-thn-auth-runtime-production` function and the external `zlp-thn-auth-runtime-prod-role`, with no generated function role. Native change-set guards require the resulting exact function, alias, and log group inventory and reject unrelated resources or replacement.

The full API unit suite passed 334 tests with 2 skipped; local SAM validation and native translation passed. A mocked create-stack review now traverses template sealing, change-set creation, the exact nine-resource native inventory and retained record creation. The dedicated role and function remain absent in AWS, and no production release was executed.
