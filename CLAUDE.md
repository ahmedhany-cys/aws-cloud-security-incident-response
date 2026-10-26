# CLAUDE.md: AWS Cloud Security Monitoring & Automated Incident Response

## Project goal
Build a portfolio-ready AWS security monitoring system that detects suspicious API activity and automatically produces structured incident reports, deployed entirely with Terraform, at (near) zero cost on the AWS Free Tier.

Detect with CloudTrail -> EventBridge. Respond with Lambda -> S3 incident reports. Everything is IaC, tested with controlled scenarios, and documented with an architecture diagram, test cases, CLI evidence and console screenshots.

## Hard rules (never break these)
1. **Never use or request root credentials.** Use only the AWS CLI profile named in the kickoff prompt.
2. **Never run `terraform apply` or `terraform destroy` without showing me the plan summary first and getting my explicit "yes".** Run `terraform plan -out=tfplan` and summarize: resources to add/change/destroy, and anything that could cost money.
3. **Never run `git push`, create a repo, or change repo visibility without my explicit approval** (see Phase 6).
4. **Never create IAM access keys, users with console passwords, or attach policies to my own identity.** If a permission is missing, stop and tell me exactly what to add.
5. **Only touch resources created by this project** (tag `Project = aws-sec-ir`). Never modify or delete anything else in the account.
6. **Never weaken the real audit or incident buckets during tests.** Test scenarios run against dedicated throwaway test resources created for that purpose.
7. **Never commit secrets, state, or account IDs** (see Git hygiene).
8. If any step could create cost outside the Free Tier guardrails below, **stop and ask**.
9. Work in phases. At the end of each phase, summarize what was done and wait for me to say "continue".

## Region
Deploy everything in **us-east-1**. IAM is a global service and its API events are only delivered to EventBridge in us-east-1. Keep the whole stack in one region so the IAM, CloudTrail and S3 rules all fire.

## Free Tier / cost guardrails
- Exactly **one** CloudTrail trail, management events only (read + write). **No data events, no CloudTrail Insights, no organization trail, no second trail.**
- **No CloudTrail -> CloudWatch Logs delivery** (ingestion costs money). Audit logs go to S3 only.
- Lambda: Python 3.12, 128 MB, timeout 30 s, no provisioned concurrency, no VPC, no NAT gateway.
- CloudWatch log group for the Lambda: **retention 7 days**.
- S3: SSE-S3 encryption, versioning on, lifecycle rule expiring objects after 30 days (and noncurrent versions after 7).
- EventBridge: default bus only, AWS-event rules only (free).
- SNS email notification is **optional** and off by default (`enable_email_alerts = false`). If enabled, one topic, one email subscription.
- No GuardDuty, Security Hub, Config, Macie or Inspector (they are not free long term and are out of scope).
- Add a `docs/cost-notes.md` explaining each service's free-tier status and what I should check in Billing.
- Check which Free Tier model my account uses (credit-based plan vs the legacy 12-month tier) and note it in the cost doc. Do not assume.

## Architecture
```
API activity (IAM, S3, CloudTrail)
        |
        v
CloudTrail (mgmt events) --> S3 audit-logs bucket
        |
        v
EventBridge (default bus) rules  --match suspicious API calls-->  Lambda (incident-processor)
                                                                        |
                                                                        v
                                                        S3 incident-reports bucket (JSON)
                                                                        |
                                                              (optional) SNS email
```

### Detection rules (EventBridge patterns)
Pattern shape (one rule per category, `detail-type = "AWS API Call via CloudTrail"`):
```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
                  "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
                  "CreatePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion"]
  }
}
```
| Category | Source | Event names | Severity |
|---|---|---|---|
| IAM policy change | aws.iam | AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy, PutUserPolicy, PutRolePolicy, PutGroupPolicy, CreatePolicy, CreatePolicyVersion, SetDefaultPolicyVersion | HIGH |
| Logging tamper | aws.cloudtrail | StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors | CRITICAL |
| S3 permission change | aws.s3 | PutBucketPolicy, DeleteBucketPolicy, PutBucketAcl, PutPublicAccessBlock, DeletePublicAccessBlock | HIGH |

Verify each event name against the AWS docs/CloudTrail event reference before finalizing. Do not guess.

### Lambda: `incident-processor`
- Input: the EventBridge event. Output: one JSON incident report per event written to `s3://<incident-bucket>/incidents/YYYY/MM/DD/<eventID>.json` (the CloudTrail `eventID` makes writes idempotent).
- Report schema (document it in `docs/incident-schema.md`):
  `incident_id, detected_at, event_time, severity, category, event_name, event_source, aws_region, actor {type, arn, user_name}, source_ip, user_agent, resources, request_parameters (sanitized), error_code, recommended_actions[], raw_event_id`
- Severity and recommended actions come from a lookup table in code, not hardcoded per-rule in Terraform.
- Sanitize: never store full session tokens or credentials if present in the event.
- Structured JSON logging to CloudWatch; never swallow exceptions silently. Failed invocations must be visible in logs.
- Unit tests with `pytest` using sample events in `tests/events/*.json`. These must pass without any AWS access.

### IAM (least privilege)
- Lambda execution role: `s3:PutObject` on `incident-bucket/incidents/*` only, plus `logs:CreateLogStream` / `logs:PutLogEvents` on its own log group only. No `*` resources except where AWS genuinely requires it (explain each in a code comment).
- Lambda resource policy: only `events.amazonaws.com` from the specific rule ARNs may invoke it.
- S3 bucket policies: deny non-TLS (`aws:SecureTransport = false`); CloudTrail bucket policy scoped to the trail's ARN and `aws:SourceArn`.
- Block Public Access ON for all project buckets.
- Draft (do not attach) a scoped deployer policy JSON in `docs/deployer-policy.json` for services this project uses, so I can review and attach it myself.

## Repository layout
```
.
├── CLAUDE.md
├── README.md
├── .gitignore
├── terraform/
│   ├── versions.tf  providers.tf  variables.tf  outputs.tf  main.tf
│   └── modules/ (optional: cloudtrail, detection, responder, test_resources)
├── lambda/
│   ├── incident_processor.py
│   └── requirements.txt   (keep dependencies minimal; boto3 is built in)
├── tests/
│   ├── events/*.json
│   └── test_incident_processor.py
├── scripts/
│   ├── run_test_scenarios.sh
│   ├── collect_evidence.sh
│   └── redact.sh        (replaces 12-digit account IDs and emails in saved evidence)
└── docs/
    ├── architecture.md  (Mermaid diagram + explanation) and architecture.png
    ├── design-decisions.md  (why each rule, permission and cost choice; written for interview Q&A)
    ├── test-cases.md
    ├── incident-schema.md
    ├── cost-notes.md
    ├── teardown.md
    ├── evidence/        (redacted CLI/JSON outputs)
    └── screenshots/     (redacted PNGs + CHECKLIST.md)
```
Terraform: version >= 1.5, `aws` provider `~> 5.0`, local state (gitignored), all resources tagged (`Project`, `Environment=lab`, `ManagedBy=terraform`), no hardcoded account IDs (use `aws_caller_identity`), unique bucket names via a suffix variable or `random_id`. Run `terraform fmt` and `terraform validate` before every plan.

## Test scenarios (controlled, reversible)
Create dedicated test resources in Terraform (a no-permission test IAM user, a harmless test managed policy, a throwaway test S3 bucket). All scenarios target only these.

| ID | Scenario | Command idea | Expected |
|---|---|---|---|
| T1 | IAM policy attach | `aws iam attach-user-policy` (test user, test policy), then detach | HIGH incident for AttachUserPolicy |
| T2 | Inline policy put | `aws iam put-user-policy` on test user, then delete | HIGH incident for PutUserPolicy |
| T3 | Disable logging | `aws cloudtrail stop-logging` then **immediately** `start-logging` | CRITICAL incident; trail confirmed logging again via `get-trail-status` |
| T4 | S3 policy change | `put-bucket-policy` on the **test** bucket (harmless policy), then delete | HIGH incident for PutBucketPolicy |
| T5 | Public access block removal | `delete-public-access-block` on the **test** bucket, then restore | HIGH incident |
| T6 | Negative test | benign call (e.g. `aws iam list-users`, `aws s3 ls`) | **No** incident created |

For each: record the command, timestamp, the CloudTrail event found via `aws cloudtrail lookup-events`, the Lambda invocation (log excerpt) and the resulting S3 incident JSON. CloudTrail -> EventBridge delivery can take a few minutes; poll with a timeout rather than assuming failure. Always restore state afterwards (especially T3). Save redacted outputs in `docs/evidence/` and fill in `docs/test-cases.md` with pass/fail.

## Documentation deliverables
- **README.md**: overview, architecture diagram, detection table, prerequisites, deploy steps, how to run tests, results summary (with screenshots), cost notes, teardown, lessons learned, future improvements (e.g. root-login detection, SNS/Slack alerts, automated remediation, GuardDuty/Security Hub integration, multi-account).
- **docs/architecture.md**: Mermaid diagram plus component explanations. Also export `architecture.png` if a renderer is available (e.g. `mmdc`); if not, tell me and leave the Mermaid source.
- **docs/design-decisions.md**: explain every detection pattern, IAM permission and cost decision, and the trade-offs. This is for me to study before interviews. Write it in plain language.

## Screenshots phase (Phase 5)
1. First check which browser tools are available in this session (Claude in Chrome, a Playwright/other MCP, etc.). Do not assume.
2. If a browser tool is available: **I will log in and complete MFA myself in my own browser.** You never see or type my password or MFA code. Ask me to confirm when I'm signed in as the lab IAM user (not root), then capture the screens below. If my session expires, stop and ask me to sign in again.
3. If no browser tool is available: do not fake anything. Generate `docs/screenshots/CHECKLIST.md` listing each screenshot, the exact console URL/path, what must be visible, and the filename to use, and I will capture them.
4. Required screenshots: (1) `terraform apply` summary output, (2) CloudTrail trail overview + status Logging, (3) CloudTrail event history showing a test event, (4) EventBridge rules list, (5) one rule's event pattern, (6) Lambda function overview, (7) Lambda CloudWatch log excerpt for a detection, (8) incident-reports bucket with objects, (9) an incident JSON, (10) S3 Block Public Access settings, (11) Billing / Free Tier usage page.
5. **Redact the 12-digit account ID** (and email addresses) in every screenshot before it is committed. If you cannot redact automatically, flag the file and tell me to blur it manually.

## Git hygiene
`.gitignore` must include at minimum: `.terraform/`, `*.tfstate`, `*.tfstate.*`, `*.tfvars` (commit a `terraform.tfvars.example` instead), `tfplan`, `crash.log`, `.env`, `*.pem`, `__pycache__/`, `.venv/`, `lambda/*.zip`, `.DS_Store`.
Before any push, run and show me the results of:
- `git ls-files | grep -E '(tfstate|tfvars|\.env|\.pem)'` (must return nothing except `*.example`)
- `git grep -nE '[0-9]{12}'` (review every hit; only placeholder IDs such as `123456789012` are acceptable)
- `git grep -nE 'AKIA[0-9A-Z]{16}'` (must return nothing)
- `gitleaks detect` if installed.

## Phases and gates
0. **Preflight**: verify `aws sts get-caller-identity`, region, tool versions, budget alert exists (ask me; do not create billing resources). Draft `docs/deployer-policy.json`. Write the plan. *Gate: I approve.*
1. **Terraform foundation**: providers, buckets, trail, IAM. `fmt`/`validate`/`plan`. *Gate: I approve the plan, then apply.*
2. **Detection + response**: EventBridge rules, Lambda code, permissions, unit tests (`pytest` green). *Gate: plan approval, then apply.*
3. **Testing**: run T1 to T6, collect redacted evidence, fill in `docs/test-cases.md`. *Gate: I review results.*
4. **Documentation**: README, architecture diagram, design decisions, cost notes, teardown.
5. **Screenshots**: as described above. *Gate: I confirm they look right and are redacted.*
6. **GitHub**: run the hygiene checks, show me the file list and repo name/visibility, wait for approval, then create the repo with `gh repo create`, commit in logical steps (conventional commit messages), and push. Do not create the repo until I confirm name and visibility.

Teardown (`docs/teardown.md`): empty versioned buckets first (`aws s3api` delete-objects for versions and delete markers), then `terraform destroy`. Only run it when I ask. After destroying, confirm no project-tagged resources remain.

## Definition of done
- `terraform apply` is reproducible from a clean clone using only the README.
- All six test scenarios documented with evidence (T1 to T5 produce incidents; T6 produces none).
- Unit tests pass.
- No secrets, state files or real account IDs in the repo.
- Diagram, README, test cases, design decisions, cost notes and screenshots (or checklist) are present.
- Repo pushed with approval, and a final summary lists any limitations honestly.

## Style
- Explain what you're about to do before doing it, in one or two sentences.
- Prefer small, reviewable commits and small diffs.
- If something fails, show the real error and your diagnosis. Never mark a test as passed unless you observed the evidence.
- Do not invent AWS behavior. Check the AWS docs when unsure.
