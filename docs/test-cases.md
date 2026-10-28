# Test cases

All scenarios run from `scripts/run_test_scenarios.sh` against the dedicated
test resources only (test user, test policy, test bucket). T3 touches the real
trail because there is only one, and restarts logging immediately. Evidence is
saved redacted under `docs/evidence/`.

Status legend: PASS = incident observed with matching `event_name` and the
expected severity, plus Lambda log line and CloudTrail record; FAIL = not
observed within the timeout; NOT RUN = not executed yet.

| ID | Scenario | Target | Command | Restore | Expected | Result | Evidence |
|---|---|---|---|---|---|---|---|
| T1 | IAM policy attach | test user + test policy | `aws iam attach-user-policy` | `detach-user-policy` | HIGH incident, `AttachUserPolicy` | **PASS** | `T1-*` |
| T2 | Inline policy put | test user | `aws iam put-user-policy` | `delete-user-policy` | HIGH incident, `PutUserPolicy` | **PASS** | `T2-*` |
| T3 | Disable logging | project trail | `aws cloudtrail stop-logging` | `start-logging` immediately; `get-trail-status` must show `IsLogging: true` | CRITICAL incident, `StopLogging` | **PARTIAL: 2 of 3 attempts** (see below) | `T3-*`, `run1/T3-*`, `run2-T3/` |
| T4 | S3 policy change | test bucket | `aws s3api put-bucket-policy` (harmless deny-non-TLS policy with a marker Sid) | `delete-bucket-policy`, then re-put the original policy | HIGH incident, `PutBucketPolicy` | **PASS** | `T4-*` |
| T5 | Public access block removal | test bucket | `aws s3api delete-public-access-block` (CloudTrail event name: `DeleteBucketPublicAccessBlock`) | `put-public-access-block` with all four flags true | HIGH incident, `DeleteBucketPublicAccessBlock` | **PASS** after a rule fix (failed on run 1) | `T5-*`, `run1/T5-attempt1-diagnosis.txt` |
| T7 | Scheduled trail health check | project trail | `aws cloudtrail stop-logging`, then invoke the health-check Lambda | `start-logging` immediately; `get-trail-status` must show `IsLogging: true`; a second check must report healthy | CRITICAL `TrailNotLogging` incident, plus at least one run triggered by EventBridge Scheduler | **PASS** (run 5) | `T7-*`, `run4-T7-scriptbug/` |
| T6 | Negative test | none | `aws iam list-users`, `aws s3 ls` | n/a | **No** incident within the window | **PASS** | `T6-*` |

## Unit tests (no AWS access)

`pytest` covers classification for every rule event name, schema completeness,
actor extraction (IAM user, assumed role, root), sanitization of secrets,
idempotent key naming, the S3 write, optional SNS publish, loud failure on bad
input or S3 errors, and JSON-line logging.

Latest run: 86 passed (2026-10-28).

| File | Tests | Covers |
|---|---|---|
| `test_incident_processor.py` | 24 | original classification, schema, actor, sanitization, idempotent keys, logging, S3 event-name regression |
| `test_trail_health_check.py` | 8 | scheduled health check |
| `test_new_incident_types.py` | 28 | the five new types, every scoring modifier, severity bands, remediation commands |
| `test_resilience.py` | 26 | missing events and fields, duplicate events, failed notifications, the full synthetic scenario |

## Simulation tests (2026-10-28, offline)

| ID | Scenario | Expected | Result |
|---|---|---|---|
| S1 | Five new incident types from synthetic EventBridge events | correct category, tactic, score and specific remediation | PASS |
| S2 | Failed SNS alert | report stored first, `alert_failed` logged with S3 key, invocation fails | PASS |
| S3 | Retry after failed alert | same S3 key overwritten, alert sent once on retry | PASS |
| S4 | S3 write fails | no alert sent | PASS |
| S5 | Duplicate EventBridge delivery | one report; alert at-least-once (two sends, documented) | PASS |
| S6 | Duplicate and conflicting records in a log | duplicates counted once; conflict flagged, first copy kept | PASS |
| S7 | Records missing eventID / eventTime / eventName / eventSource, or bad timestamp | rejected with reason, run continues | PASS |
| S8 | Missing events: trail stopped and restarted / never restarted | visibility gap reported with duration / reported as still open | PASS |
| S9 | Full scenario: shuffled log of 23 records | sorted timeline, 2 incidents, campaign score 100, backdoor identity linked | PASS |

Evidence: [evidence/simulation/timeline.md](evidence/simulation/timeline.md).

## Run log

All runs on 2026-10-26 against the deployed stack in us-east-1. Times are UTC.
Every PASS below was confirmed by looking at the incident JSON in S3, the
matching `incident_written` line in the Lambda log, and the CloudTrail record
from `lookup-events`. After all runs, `terraform plan` reported no changes,
which confirms every scenario restored its target.

| Test | Attempt | Result | What was observed |
|---|---|---|---|
| T1 | run 2 | PASS | `AttachUserPolicy` HIGH incident about 10 s after the call. Test user has no policies again. |
| T2 | run 2 | PASS | `PutUserPolicy` HIGH incident. Inline policy deleted again. |
| T3 | run 1 | PASS | `StopLogging` CRITICAL incident 3 s after the call. Trail logging again 1 s later. |
| T3 | run 2 | **FAIL** | No incident within 900 s. CloudTrail Event history recorded the call, but the Lambda was never invoked. Trail logging again. |
| T3 | run 3 | PASS | `StopLogging` CRITICAL incident 27 s after the call. Trail logging again. |
| T4 | run 2 | PASS | `PutBucketPolicy` HIGH incident. The restore steps also raised `DeleteBucketPolicy` and `PutBucketPolicy` incidents, which is correct. Original policy restored. |
| T5 | run 1 | **FAIL** | No incident. The rule listed the API name `DeletePublicAccessBlock`; CloudTrail logs `DeleteBucketPublicAccessBlock`. |
| T5 | run 2 | PASS | After the rule fix: `DeleteBucketPublicAccessBlock` HIGH incident, and the restore raised a `PutBucketPublicAccessBlock` incident. All four block flags back on. |
| T7 | run 4 | **FAIL (script bug)** | The check wrote the CRITICAL incident, reported healthy after the restore, and ran twice on schedule. The script's run counter used `length(events)`, which the CLI prints once per page, so the integer test broke. Script fixed. |
| T7 | run 5 | PASS | CRITICAL `TrailNotLogging` incident while the trail was stopped (a few seconds), `healthy` after restore, and a scheduler-triggered run within about a minute. |
| T6 | run 2 | PASS | `aws iam list-users` and `aws s3 ls` produced no incident. Newest object in the incident bucket predates T6, and the Lambda logged nothing. |

### T3: why it is only partial

T3 stops the account's only trail. AWS documents that EventBridge receives
CloudTrail API events only while a trail is logging, so whether the
`StopLogging` call itself reaches EventBridge is a race. Two of three
attempts were detected. This is a real limitation of a single-trail design,
explained with possible fixes in
[design-decisions.md](design-decisions.md#12-the-stoplogging-blind-spot-observed-in-testing).
The failed attempt's evidence is in `evidence/run2-T3/T3-diagnosis.txt`.

### T7: closing the T3 gap

T7 tests the scheduled health check added after T3 was found to be partial.
It does not rely on CloudTrail delivering the `StopLogging` event: it asks
CloudTrail directly whether the trail is logging. With the schedule at 5
minutes, a stopped trail is reported within at most about 5 minutes, even when
EventBridge misses the `StopLogging` event.

### T5: the bug it found

The first run failed because S3's CloudTrail event names differ from its API
names. Evidence: `evidence/run1/T5-attempt1-diagnosis.txt` shows zero events
under the API names and real `PutBucketPublicAccessBlock` events from the
Terraform apply. The rule and Lambda lookup were corrected, redeployed with a
0-add / 2-change / 0-destroy plan, and T5 passed on run 2.
