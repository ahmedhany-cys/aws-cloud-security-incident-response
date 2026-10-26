# Build log

Running record of what was done, what was verified, and decisions taken.

## 2026-10-23 — Hand-off guide

- Session started with no project folder. Searched the whole home directory, iCloud Drive, Spotlight and earlier session folders for `CLAUDE.md`: **not found**. Build is blocked until the spec is provided (see docs/my-tasks.md step 0).
- Environment checks run:
  - `aws sts get-caller-identity --profile sec-ir` → profile `sec-ir` does not exist (profiles present: default, siem_project, siem_project_attacker).
  - `aws --version` → 2.36.40 OK.
  - `terraform version` → not installed.
  - `gh auth status` → gh not installed.
  - `python3 --version` → 3.14.7 OK; `pytest` and `boto3` not installed.
  - `git --version` → 2.39.5 OK.
  - Browser tools: built-in browser pane and Claude in Chrome both available.
- Wrote docs/my-tasks.md with every manual step. docs/deployer-policy.json deferred until CLAUDE.md lists the services.
- Decision: did not install any tools or create any AWS profile, per the "ask before installing software" rule.

## 2026-10-23 — Tool install (approved by user)

- `brew tap hashicorp/tap && brew install hashicorp/tap/terraform gh` → Terraform v1.17.0, gh 2.103.0.
- Created project venv `.venv` and installed boto3 1.43.118 and pytest 9.1.1 (system Python untouched).
- `gh auth status` → still not logged in; user must run `gh auth login` (my-tasks step 5).
- Still waiting on: CLAUDE.md location (path was blank in the user's reply), AWS profile `sec-ir`, deployer policy, budget, gh login.

## 2026-10-23 — Spec received, project folder chosen, Phases 0-2 code written

- Spec: `/Users/ahmedhany/Downloads/CLAUDE.md`, copied into the project root. Project folder chosen by the user via the folder picker: `aws project (1)` in the home directory. Session moved there; venv recreated.
- Verified every detection event name against the IAM, CloudTrail and S3 API operation lists (docs.aws.amazon.com API references). All 18 names exist as spelled. Attempts to fetch the EventBridge/CloudTrail integration page returned only the title; the design does not depend on it because a trail is created anyway.
- Phase 0 (preflight, partial): tool versions OK; `aws sts get-caller-identity --profile sec-ir` still fails (profile missing); Free Tier plan check deferred until the profile exists; `docs/deployer-policy.json` drafted.
- Phase 1 + 2 code: Terraform root module (versions, providers, variables, main, s3, cloudtrail, detection, responder, notifications, test_resources, outputs, tfvars example). `terraform fmt` clean, `terraform init -backend=false` + `validate` → Success.
- Lambda `lambda/incident_processor.py` with lookup table, sanitization, structured logging, idempotent S3 key. 7 sample events, 23 unit tests → all pass (`.venv/bin/python -m pytest`). One fix along the way: the log handler now resolves `sys.stdout` at emit time so pytest capture and the Lambda runtime both see the JSON lines.
- Scripts: `run_test_scenarios.sh` (T1-T6 with restore + polling + evidence), `collect_evidence.sh`, `redact.sh`, `common.sh`, `empty_bucket.sh`. `bash -n` clean; redact.sh tested on a sample line.
- Docs: README, architecture (Mermaid only; no renderer installed), design-decisions, incident-schema, cost-notes (Free Tier model TBD), teardown, test-cases (NOT RUN), screenshots/CHECKLIST.md, evidence/README.
- Decisions: root module split by file instead of modules (spec says modules optional); test bucket keeps a Terraform-managed deny-TLS policy so T4 can overwrite and restore a real policy; audit/incident buckets `force_destroy=false`; Lambda arm64; trail single-region with global events.
- Not done (blocked on user): AWS profile, deployer policy attachment, budget, gh login, bucket suffix → no `terraform plan` against AWS yet, no apply, no T1-T6, no screenshots, no push.
