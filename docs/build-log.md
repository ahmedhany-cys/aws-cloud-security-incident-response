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

- Spec: `~/Downloads/CLAUDE.md`, copied into the project root. Project folder chosen by the user via the folder picker: `aws project (1)` in the home directory. Session moved there; venv recreated.
- Verified every detection event name against the IAM, CloudTrail and S3 API operation lists (docs.aws.amazon.com API references). All 18 names exist as spelled. Attempts to fetch the EventBridge/CloudTrail integration page returned only the title; the design does not depend on it because a trail is created anyway.
- Phase 0 (preflight, partial): tool versions OK; `aws sts get-caller-identity --profile sec-ir` still fails (profile missing); Free Tier plan check deferred until the profile exists; `docs/deployer-policy.json` drafted.
- Phase 1 + 2 code: Terraform root module (versions, providers, variables, main, s3, cloudtrail, detection, responder, notifications, test_resources, outputs, tfvars example). `terraform fmt` clean, `terraform init -backend=false` + `validate` → Success.
- Lambda `lambda/incident_processor.py` with lookup table, sanitization, structured logging, idempotent S3 key. 7 sample events, 23 unit tests → all pass (`.venv/bin/python -m pytest`). One fix along the way: the log handler now resolves `sys.stdout` at emit time so pytest capture and the Lambda runtime both see the JSON lines.
- Scripts: `run_test_scenarios.sh` (T1-T6 with restore + polling + evidence), `collect_evidence.sh`, `redact.sh`, `common.sh`, `empty_bucket.sh`. `bash -n` clean; redact.sh tested on a sample line.
- Docs: README, architecture (Mermaid only; no renderer installed), design-decisions, incident-schema, cost-notes (Free Tier model TBD), teardown, test-cases (NOT RUN), screenshots/CHECKLIST.md, evidence/README.
- Decisions: root module split by file instead of modules (spec says modules optional); test bucket keeps a Terraform-managed deny-TLS policy so T4 can overwrite and restore a real policy; audit/incident buckets `force_destroy=false`; Lambda arm64; trail single-region with global events.
- Not done (blocked on user): AWS profile, deployer policy attachment, budget, gh login, bucket suffix → no `terraform plan` against AWS yet, no apply, no T1-T6, no screenshots, no push.

## 2026-10-26 — Fix: invalid action in deployer policy

- User reported an error while setting up. The terminal showed none and the `sec-ir` profile did not exist yet, so the likely source was the console policy editor.
- Checked all 135 actions in `docs/deployer-policy.json` against the AWS service reference JSON (servicereference.us-east-1.amazonaws.com). One was invalid: `budgets:DescribeBudgets` (an API name; the IAM action is `budgets:ViewBudget`, already present). Removed it. Re-check: 0 invalid actions. Policy size 4.9k of the 6,144-character limit.

## 2026-10-26 — Console setup in the built-in browser (at the user's request)

- User was signed in to the console in the built-in browser as their own IAM user (not root). Claude fixed the policy editor error in place (deleted the invalid `budgets:DescribeBudgets` line; editor then reported 0 errors). The user clicked Create; console confirmed "Policy aws-sec-ir-deployer-policy created."
- Claude created IAM user `aws-sec-ir-deployer`: console access disabled, `aws-sec-ir-deployer-policy` attached directly, tag `Project=aws-sec-ir`. Verified on the user's Permissions tab.
- Validator suggestions (4, all "redundant action/resource" from the `s3:GetBucket*`/`s3:PutBucket*` wildcards and overlapping ARN patterns) left as is: harmless, and the explicit names aid review.
- Not done by Claude, by rule: access key creation (CLAUDE.md rule 4 + kickoff rule), billing budget (Phase 0 says do not create billing resources), GitHub OAuth approval (user's own login). Started `gh auth login --web` in a terminal tab for the user to complete.

## 2026-10-26 — Preflight, deploy, screenshots

- Verified: `sec-ir` = `aws-sec-ir-deployer`; GitHub logged in; budget `aws-sec-ir-budget` exists (plus 2 pre-existing account budgets); Free Tier plan = credit-based FREE plan, ACTIVE, expires 2026-11-30 (recorded in cost-notes.md).
- Cost check before planning: `describe-trails --include-shadow-trails` returned no trails, so the project trail is the account's only (free) copy of management events.
- Bucket suffix chosen by Claude: `ahr4827` (initials + 4 digits, per kickoff settings). All three names were free (HEAD → 404).
- `terraform fmt -check`, `validate`, `plan -out=tfplan` → 37 to add, 0 change, 0 destroy; no data events, Insights, CW Logs delivery, VPC or provisioned concurrency. Met the autonomy criteria, so applied: "Apply complete! Resources: 37 added, 0 changed, 0 destroyed."
- Post-apply checks (`scripts/collect_evidence.sh`): trail IsLogging=true and already delivering; Lambda python3.12/128 MB/30 s; Lambda resource policy has exactly 3 statements, principal events.amazonaws.com, SourceArn = each rule; all resources carry Project=aws-sec-ir.
- Found during T1 evidence review: the `eventbridge_rule` field was always null (the EventBridge envelope's `resources` lists the API call's resources, not the matching rule). Removed the field from code, schema doc and sample events; redeploy pending until the scenarios finish.
- Redaction extended: IPv4 addresses (operator's public IP appeared as `source_ip`), access key IDs (AKIA/ASIA, present in CloudTrail lookup output) and IAM unique IDs (AIDA/AROA).
- Screenshots: captured all 11 with the built-in browser while the user was signed in as their IAM user (not root). Redaction was applied to the page text before capture (account ID, emails, IPs, key IDs, principal IDs), so no raw image contains them. #1 (terraform apply) and #9 (incident JSON) are renderings of the real captured CLI output via macOS Quick Look, because they are terminal output, not console pages; the S3 "Open" button was blocked by the browser and its pre-signed URL was not used.
- Expected side effect noted: T4 and T5 restore steps (re-putting the bucket policy / public access block) are themselves S3 permission changes, so they also produce HIGH incidents. That is correct behaviour.

## 2026-10-26 — Testing (Phase 3), fixes, documentation

- Run 1 (T1-T5): T1-T4 PASS with full evidence. T5 FAIL: no incident. Diagnosis via `lookup-events` and the S3 user guide's CloudTrail event list: S3 logs the PublicAccessBlock APIs as `PutBucketPublicAccessBlock` / `DeleteBucketPublicAccessBlock` (bucket) and `PutAccountPublicAccessBlock` / `DeleteAccountPublicAccessBlock` (account). The spec, and my 2026-10-23 check against the *API* reference, used the API names. Stopped the run (state already restored), saved the diagnosis to `evidence/run1/`.
- Fix: rule + Lambda lookup now use the four CloudTrail names; added a regression unit test (24 tests pass). Also removed the always-null `eventbridge_rule` field. Plan: 0 add, 2 change in place, 0 destroy → applied.
- Run 2 (T1-T6): T1, T2, T4, T5, T6 PASS. T3 FAIL: CloudTrail Event history recorded `StopLogging`, but the Lambda was never invoked. The EventBridge user guide says CloudTrail API events require a trail with logging enabled; T3 stops the only trail, so delivery of that event is a race. Trail confirmed logging again.
- Run 3 (T3 only, to characterise the race rather than to retry until green): PASS, CRITICAL incident in 27 s. Final T3 status reported as PARTIAL (2 of 3). All attempts kept as evidence.
- Not built (needs owner approval, adds an unlisted service): scheduled trail health check. Documented in design-decisions section 12 and my-tasks.
- `terraform plan -detailed-exitcode` after all runs: exit 0, no drift, so every scenario fully restored its target.
- Evidence re-redacted with the extended script; deleted local `.plan*.txt` dumps (contained the account ID) and gitignored them.
- Screenshots #8 and #9 retaken after run 2 (14 incident objects; post-fix incident JSON without the removed field).
- Docs completed: test-cases (per-attempt table), README results + screenshot grid + lessons learned, design decisions (S3 event names, restore incidents, StopLogging blind spot), evidence index, screenshot checklist status, cost notes (Free plan expiry), my-tasks statuses.
- `docs/architecture.png` not produced: no Mermaid renderer installed and installing one was not approved. Mermaid source renders on GitHub.

## 2026-10-26 — Phase 6: GitHub

- Hygiene checks on HEAD and full history: no state/tfvars/env/pem tracked (only `terraform.tfvars.example`); every 12-digit hit reviewed and placeholder-only (fake sequential UUIDs in test events/docs, provider checksums in `.terraform.lock.hcl`); no `AKIA` keys; the real account ID and the owner's Gmail address appear in zero commits. `gitleaks` not installed, so skipped.
- Commit authorship rewritten (before the first push) to the GitHub no-reply address so the owner's email is not published.
- Created public repo `ahmedhany-cys/aws-cloud-security-incident-response` with `gh repo create --public --source . --push`.

## 2026-10-26 — Scheduled trail health check (owner approved)

- Owner approved building the fix for the T3 blind spot. Added `health_check_handler` (same module and zip as the incident processor), `terraform/health_check.tf` (Lambda, least-privilege role, 7-day log group, Scheduler group + schedule at `rate(5 minutes)`, scheduler role limited to invoking that one function), 8 unit tests (32 total pass), scenario T7, and new field `detection_source` in all reports.
- Verified against the AWS service reference: `cloudtrail:GetTrailStatus` supports the trail resource type (no `*`), and all Scheduler actions scope to `schedule-group/aws-sec-ir` and `schedule/aws-sec-ir/*`.
- Deployer lacked Scheduler permissions (confirmed by an AccessDenied on `ListScheduleGroups`). Drafted the two new statements; the owner's first edit did not save (policy still v1), second edit saved as v2 and was verified before applying.
- Plan shown to the owner and approved: 8 add, 1 change (incident processor code), 0 destroy. Applied: "8 added, 1 changed, 0 destroyed."
- T7 run 4: health check worked (CRITICAL incident, healthy after restore, 2 scheduled runs) but recorded FAIL because the script counted runs with `length(events)` and the CLI printed one value per page. Kept as evidence, fixed the counter (`wc -w` over event IDs), reran.
- T7 run 5: PASS. Trail logging again; `terraform plan` shows no drift.

## 2026-10-26 — Commit attribution cleanup (owner's request)

- Removed the `Co-Authored-By` trailer from all 14 commits (`git filter-branch --msg-filter`; file contents unchanged, verified with an empty diff) and force-pushed `main` with a lease, after the owner allowed force-push for this repo.
- Verified on GitHub: 14 commits, 0 co-author lines, only `ahmedhany-cys` as author, `stats/contributors` = `ahmedhany-cys: 14`. The repo page's contributor sidebar is cached separately and refreshes on the next push.

## 2026-10-28 — Five new incident types, scoring, timeline, resilience tests

- Request: five new simulated incident types; an incident timeline from synthetic CloudTrail JSON; severity scoring and remediation recommendations; tests for missing events, duplicate events and failed notifications.
- Event names verified first (lesson from T5): all 12 IAM/EC2/KMS names exist in the AWS service reference; KMS CloudTrail examples show ScheduleKeyDeletion and DisableKey as logged names; EC2's CloudTrail example logs the API name. KMS API reference confirms CancelKeyDeletion leaves the key Disabled (so remediation re-enables it).
- New types: identity_creation, mfa_tampering, role_trust_change, network_exposure, kms_key_destruction. Added to the Lambda lookup and as 5 EventBridge rules in Terraform (not yet applied).
- Scoring: 0-100 score from per-event base plus context modifiers, bands CRITICAL/HIGH/MEDIUM/LOW; original rules keep their severities. Reports now include severity_score, score_factors, tactic and remediation (schema 1.1).
- Notifications: report stored before alerting; alert failure logs `alert_failed` with the S3 key and raises NotificationError so Lambda retries; S3 failure never alerts. At-least-once alerts documented.
- Simulation: `simulation/generate_scenario.py` (deterministic messy CloudTrail log + 5 sample events), `simulation/timeline.py` (validate, de-duplicate, sort, score, find logging gaps, correlate incidents). Fixed during review: a conflicting duplicate kept in place of the original because of shuffle order (generator now appends it after), failed calls no longer get roll-back steps, wording.
- Tests: 32 -> 86, all passing.
- 2026-10-28: owner approved the plan. Applied: "15 added, 2 changed, 0 destroyed". Verified live: 8 rules ENABLED with one target each; Lambda policy has exactly 8 invoke statements (one per rule); `terraform plan` shows no drift.
- Live smoke test (T1 repeated on the test user): the deployed Lambda wrote a schema 1.1 report, score 65 HIGH, tactic privilege_escalation, with remediation commands; test user restored. Evidence: `docs/evidence/scoring-smoke/`. The five new types themselves remain simulation-only (see design decisions, section 14).
