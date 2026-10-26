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
| T1 | IAM policy attach | test user + test policy | `aws iam attach-user-policy` | `detach-user-policy` | HIGH incident, `AttachUserPolicy` | NOT RUN | `T1-*` |
| T2 | Inline policy put | test user | `aws iam put-user-policy` | `delete-user-policy` | HIGH incident, `PutUserPolicy` | NOT RUN | `T2-*` |
| T3 | Disable logging | project trail | `aws cloudtrail stop-logging` | `start-logging` immediately; `get-trail-status` must show `IsLogging: true` | CRITICAL incident, `StopLogging` | NOT RUN | `T3-*` |
| T4 | S3 policy change | test bucket | `aws s3api put-bucket-policy` (harmless deny-non-TLS policy with a marker Sid) | `delete-bucket-policy`, then re-put the original policy | HIGH incident, `PutBucketPolicy` | NOT RUN | `T4-*` |
| T5 | Public access block removal | test bucket | `aws s3api delete-public-access-block` | `put-public-access-block` with all four flags true | HIGH incident, `DeletePublicAccessBlock` | NOT RUN | `T5-*` |
| T6 | Negative test | none | `aws iam list-users`, `aws s3 ls` | n/a | **No** incident within the window | NOT RUN | `T6-*` |

## Unit tests (no AWS access)

`pytest` covers classification for every rule event name, schema completeness,
actor extraction (IAM user, assumed role, root), sanitization of secrets,
idempotent key naming, the S3 write, optional SNS publish, loud failure on bad
input or S3 errors, and JSON-line logging.

Latest run: 23 passed (2026-10-23).

## Run log

_Filled in by Phase 3._
