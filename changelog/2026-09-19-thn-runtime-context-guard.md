# THN TEST runtime context guard

The first dedicated `verify` run stopped before acquiring AWS credentials. The
controller required a concrete Python `dict` for its environment even though
GitHub invokes the CLI with `os.environ`, a mapping. The existing tests passed
plain dictionaries and therefore missed this entrypoint mismatch.

The guard now accepts a mapping while retaining every exact repository, TEST
branch, event, source SHA, account and role check. A regression test exercises
the real `--check-context` CLI path with `os.environ`. The private-plan selector
validation was aligned with the already approved first-provisioning selector;
the sealed plan digest and package-byte checks remain unchanged. No AWS write
was attempted by the failed verification.
