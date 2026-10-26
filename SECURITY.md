# Security policy

This is a personal lab project that deploys security monitoring into a single
AWS account. There is no hosted service to attack, but the Terraform, IAM
policies and Lambda code are meant to be a sound reference, so reports about
them are welcome.

## Reporting a vulnerability

Please do not open a public issue for anything that could weaken a deployment,
for example:

- an IAM or bucket policy that grants more than the docs claim,
- a way to make the Lambda drop, mangle or silently skip an incident,
- a redaction bypass that could leak account IDs, IPs or key IDs from evidence,
- a cost guardrail that can be exceeded without changing a variable.

Use GitHub's private vulnerability reporting instead: open the **Security** tab
of this repository and choose **Report a vulnerability**. If that button is not
available, open an issue titled "Security contact request" with no details and
the maintainer will reach out. Expect an acknowledgement within 7 days.

Non-sensitive hardening ideas (a new detection rule, a tighter resource ARN) can
go in a normal issue using the "Detection rule request" or "Bug report"
template.

## Scope

**In scope:** everything under `terraform/`, `lambda/`, `scripts/` and the
sample events in `tests/events/`.

**Out of scope:** AWS services themselves, and the redacted records of past test
runs under `docs/evidence/` and `docs/screenshots/`.

## How this repository stays safe

- No credentials, state files, `.tfvars`, account IDs, IPs, access key IDs or
  IAM principal IDs are committed. `scripts/redact.sh` rewrites evidence before
  it is saved, and `.gitignore` blocks the raw copies.
- GitHub secret scanning and push protection are enabled on the repository.
- Dependabot keeps the Terraform providers, Python dev dependencies and GitHub
  Actions current.
- CI runs the unit tests, Ruff, ShellCheck, `terraform fmt` and
  `terraform validate` on every push and pull request.
- The Lambda has no third-party runtime dependencies (boto3 ships with the
  runtime), which keeps the supply-chain surface small.
