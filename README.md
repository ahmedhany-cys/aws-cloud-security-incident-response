# AWS Cloud Security Monitoring and Automated Incident Response

A portfolio-ready, Terraform-deployed security monitoring pipeline for a single
AWS account. CloudTrail records management API calls, EventBridge rules match
suspicious ones, and a Lambda function writes a structured JSON incident report
to S3 for every detection. Everything runs inside the AWS Free Tier.

```
API activity (IAM, S3, CloudTrail)
        |
        v
CloudTrail (mgmt events) --> S3 audit-logs bucket
        |
        v
EventBridge (default bus) rules --match suspicious API calls--> Lambda incident-processor
                                                                        |
                                                                        v
                                                        S3 incident-reports bucket (JSON)
                                                                        |
                                                              (optional) SNS email
```

Full diagram and component descriptions: [docs/architecture.md](docs/architecture.md).

## Detection rules

| Category | EventBridge source | Event names | Severity |
|---|---|---|---|
| IAM policy change | `aws.iam` | AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy, PutUserPolicy, PutRolePolicy, PutGroupPolicy, CreatePolicy, CreatePolicyVersion, SetDefaultPolicyVersion | HIGH |
| Logging tamper | `aws.cloudtrail` | StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors | CRITICAL |
| S3 permission change | `aws.s3` | PutBucketPolicy, DeleteBucketPolicy, PutBucketAcl, PutPublicAccessBlock, DeletePublicAccessBlock | HIGH |

Why these and not others: [docs/design-decisions.md](docs/design-decisions.md).
Report format: [docs/incident-schema.md](docs/incident-schema.md).

## Repository layout

```
terraform/   root module (s3, cloudtrail, detection, responder, notifications, test_resources)
lambda/      incident_processor.py (no third-party dependencies)
tests/       pytest unit tests + sample EventBridge events
scripts/     run_test_scenarios.sh, collect_evidence.sh, redact.sh, empty_bucket.sh
docs/        architecture, design decisions, test cases, schema, cost notes, teardown,
             evidence/ (redacted outputs), screenshots/ (redacted PNGs + checklist)
```

## Prerequisites

- An AWS account and a dedicated IAM user (not root) with the policy in
  [docs/deployer-policy.json](docs/deployer-policy.json) attached, configured as
  the CLI profile `sec-ir`.
- A billing budget (Billing → Budgets → zero-spend template) so you are alerted
  if anything is ever charged.
- Terraform >= 1.5, AWS CLI v2, Python 3.12+, `gh` (for the GitHub step only).

Beginner-friendly, click-by-click setup: [docs/my-tasks.md](docs/my-tasks.md).

## Deploy

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# edit bucket_suffix (your initials + 4 digits)
terraform -chdir=terraform init
terraform -chdir=terraform fmt -check
terraform -chdir=terraform validate
terraform -chdir=terraform plan -out=tfplan
terraform -chdir=terraform apply tfplan
```

Expected: 1 trail, 3 buckets (each with versioning, encryption, lifecycle,
public access block, ownership controls, policy), 3 EventBridge rules + 3
targets + 3 Lambda permissions, 1 Lambda + role + inline policy + log group,
1 test user, 1 test policy. Nothing is created outside us-east-1.

## Run the tests

Unit tests (no AWS access needed):

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

Controlled end-to-end scenarios (T1 to T6, each restores state afterwards):

```bash
AWS_PROFILE=sec-ir scripts/run_test_scenarios.sh
```

Then collect general stack evidence:

```bash
AWS_PROFILE=sec-ir scripts/collect_evidence.sh
```

Both write redacted outputs to `docs/evidence/`. Scenario definitions and
results: [docs/test-cases.md](docs/test-cases.md).

## Results summary

_Filled in after Phase 3 (testing) and Phase 5 (screenshots)._

| ID | Scenario | Expected | Result |
|---|---|---|---|
| T1 | IAM policy attach | HIGH `AttachUserPolicy` | pending |
| T2 | Inline policy put | HIGH `PutUserPolicy` | pending |
| T3 | Stop logging (restarted immediately) | CRITICAL `StopLogging` | pending |
| T4 | Test-bucket policy change | HIGH `PutBucketPolicy` | pending |
| T5 | Test-bucket public access block removed | HIGH `DeletePublicAccessBlock` | pending |
| T6 | Benign calls | no incident | pending |

Screenshots: [docs/screenshots/](docs/screenshots/CHECKLIST.md).

## Cost

Designed for $0/month: one trail (first copy of management events is free), no
data events, no Insights, no CloudTrail → CloudWatch Logs, Lambda and
EventBridge inside always-free limits, S3 lifecycle expiry at 30 days. Details
and what to check in Billing: [docs/cost-notes.md](docs/cost-notes.md).

## Teardown

Empty the versioned buckets, then `terraform destroy`, then confirm no
`Project=aws-sec-ir` resources remain: [docs/teardown.md](docs/teardown.md).

## Lessons learned

_Filled in at the end of the build._

## Future improvements

- Root console sign-in detection (`aws.signin` / `ConsoleLogin` with `userIdentity.type = Root`).
- Access-key and user creation detection (`CreateAccessKey`, `CreateUser`, `CreateLoginProfile`).
- SNS email (already wired, `enable_email_alerts = true`) or Slack via a webhook Lambda.
- Automated remediation for CRITICAL events (auto `start-logging`), with a tightly scoped remediation role.
- GuardDuty and Security Hub integration when cost is not a constraint.
- Multi-account: organization trail + EventBridge cross-account bus to a security account.
- Severity-based routing and a small dashboard built from the incident JSON.
