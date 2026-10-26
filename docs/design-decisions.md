# Design decisions

Written in plain language as interview preparation. Each section says what was
chosen, why, and what the trade-off is.

## 1. Detection: why CloudTrail → EventBridge instead of GuardDuty or log parsing?

**Choice.** CloudTrail records every management API call. AWS also publishes those same events to the EventBridge default bus as `AWS API Call via CloudTrail`. Three EventBridge rules match specific event names and invoke a Lambda.

**Why.** It is free, near-real-time (usually well under five minutes), needs no polling, no log parsing and no always-on compute. GuardDuty would give richer, ML-based findings, but it is billed per event volume after a 30-day trial and is out of scope for a zero-cost lab. Parsing the S3 log files ourselves would add 5 to 15 minutes of delivery delay and a lot of code.

**Trade-off.** EventBridge only sees *management* events, so object-level S3 reads and writes (data events) are invisible. That is acceptable: the goal is to catch configuration and permission changes, not data exfiltration.

## 2. Why these three detection categories?

They map to the three MITRE ATT&CK tactics that matter most in an AWS account compromise:

| Category | ATT&CK tactic | Why these event names |
|---|---|---|
| IAM policy change (HIGH) | Privilege Escalation / Persistence | `Attach*Policy` and `Put*Policy` are the direct ways to grant permissions to a user, role or group. `CreatePolicy`, `CreatePolicyVersion` and `SetDefaultPolicyVersion` cover the sneakier route of editing an existing managed policy so an already-attached policy silently becomes more powerful. |
| Logging tamper (CRITICAL) | Defense Evasion | `StopLogging`, `DeleteTrail`, `UpdateTrail` and `PutEventSelectors` are the four calls an attacker uses to blind CloudTrail. Rated CRITICAL because losing the audit trail makes every other detection worthless. |
| S3 permission change (HIGH) | Exfiltration / Collection | `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketAcl`, and the public access block calls (`PutBucketPublicAccessBlock`, `DeleteBucketPublicAccessBlock` for one bucket; `PutAccountPublicAccessBlock`, `DeleteAccountPublicAccessBlock` for the whole account) are the calls that can make a bucket readable by the world. |

**API name vs CloudTrail event name (a real bug this project hit).** EventBridge matches the CloudTrail `eventName`, not the API operation name. For IAM and CloudTrail they are identical, but S3 renames some: the `PutPublicAccessBlock` / `DeletePublicAccessBlock` API calls are logged as `PutBucketPublicAccessBlock` / `DeleteBucketPublicAccessBlock` at bucket level, and as `PutAccountPublicAccessBlock` / `DeleteAccountPublicAccessBlock` at account level (S3 user guide, "Amazon S3 CloudTrail events"). The original spec listed the API names. The first test run caught it: T5 produced no incident, and `lookup-events` showed zero events named `DeletePublicAccessBlock` but real events named `PutBucketPublicAccessBlock` from the Terraform apply. The rule now lists the CloudTrail names, and a unit test stops the API-only names from coming back. Interview takeaway: always validate detection patterns against real logged events, not against API docs.

Event names were checked against the IAM, CloudTrail and S3 references on 2026-10-23, and the S3 ones re-checked against the S3 CloudTrail event list and live `lookup-events` output on 2026-10-26. The account-level public access block names are included because they are what the spec's names literally map to, but they were not exercised by a test (changing the account-level block would affect every bucket in the account). Failed attempts (`errorCode = AccessDenied`) are still matched because an *attempt* to stop logging is itself a strong signal; the report records the error code.

**Not included and why.** Root sign-in (`ConsoleLogin` from `aws.signin`) would be a natural fourth rule and is listed under future improvements. `CreateAccessKey`, `CreateUser` and `CreateLoginProfile` are also good candidates but would raise noise in a lab where the deployer legitimately creates users.

## 3. Why the severity lives in Python, not in Terraform

The spec requires a lookup table in code. Practically: changing a severity or a recommended action then needs only a Lambda code change and `terraform apply` uploads the new zip; the rule patterns in Terraform stay stable. It also means the unit tests can verify the table, and the test `test_every_rule_event_name_is_in_lookup` guarantees Terraform and Python never drift apart.

## 4. Why one trail, single region, global events on

- One trail because the first copy of management events is free; a second trail is billed.
- Single region (us-east-1) because IAM is global and its events only reach EventBridge in us-east-1. A multi-region trail would record more but detect nothing extra for this project.
- `include_global_service_events = true` so IAM calls are recorded by this trail.
- Log file validation on: free, and it lets you prove the audit logs were not modified.
- No CloudWatch Logs destination: ingestion is billed per GB and EventBridge already gives real-time access.

## 5. Why the incident key is the CloudTrail eventID

EventBridge delivers at-least-once. If the same event is delivered twice, the Lambda writes the same object twice (idempotent) instead of creating two incidents. The date prefix (`incidents/YYYY/MM/DD/`) is the event time, so reports group naturally by day and the lifecycle rule can expire them.

## 6. IAM: least privilege, and where `*` was unavoidable

| Principal | Permission | Scope | Why |
|---|---|---|---|
| Lambda role | `s3:PutObject` | `incident-bucket/incidents/*` | Only write, only under the incidents prefix. No read, list or delete, so a compromised function cannot read or destroy evidence. |
| Lambda role | `logs:CreateLogStream`, `logs:PutLogEvents` | `its own log group:*` | The `:*` suffix is unavoidable because log stream names are generated at runtime. `logs:CreateLogGroup` is not granted; Terraform pre-creates the group with 7-day retention. |
| Lambda role trust | `sts:AssumeRole` from `lambda.amazonaws.com` | `aws:SourceAccount = this account` | Prevents the confused-deputy case where a Lambda in another account assumes the role. |
| Lambda resource policy | `lambda:InvokeFunction` | `events.amazonaws.com`, `SourceArn = each rule ARN` | Only these three rules may invoke it; no other EventBridge rule, user or service. |
| CloudTrail → audit bucket | `s3:GetBucketAcl`, `s3:PutObject` | bucket and `AWSLogs/<account>/*`, `aws:SourceArn = this trail` | Standard CloudTrail bucket policy, narrowed so only this trail can write (not any trail in any account). |
| Test policy | `sts:GetCallerIdentity` | `*` | The action does not support resource-level permissions and is harmless. |
| Deployer policy (docs/deployer-policy.json) | per-service create/delete | `aws-sec-ir-*` ARNs where the service supports it; `*` only for List/Describe/Lookup calls that have no resource ARN | So the deployer can only build and tear down project-prefixed resources. |

## 7. S3 hardening

All three buckets: Block Public Access (all four flags), ACLs disabled (`BucketOwnerEnforced`), versioning, SSE-S3, lifecycle (30 d current / 7 d noncurrent / abort multipart after 7 d) and a `Deny` on `aws:SecureTransport = false`. SSE-S3 rather than SSE-KMS because KMS keys and requests cost money and CloudTrail does not need customer-managed keys for a lab.

The audit and incident buckets have `force_destroy = false` so a stray `terraform destroy` fails instead of wiping evidence; teardown.md explains how to empty them deliberately.

## 8. Why the test resources exist

Rule 6 says never weaken the real buckets or trail during tests. T1, T2, T4 and T5 therefore act on a throwaway user, policy and bucket created by Terraform. T3 (stop-logging) necessarily touches the real trail because there is only one; the script restarts logging in the very next command and fails hard if `get-trail-status` does not show `IsLogging: true`.

The test bucket deliberately has a Terraform-managed bucket policy so T4 has something realistic to overwrite and restore.

## 9. Lambda operational choices

- Python 3.12, 128 MB, 30 s, arm64: the work is a few KB of JSON and one `PutObject`; this is the smallest, cheapest shape.
- No VPC: a VPC-attached Lambda would need NAT or VPC endpoints to reach S3, and NAT is the single most common surprise cost on the free tier.
- Structured JSON logs (one JSON object per line) so CloudWatch Logs Insights can query `severity`, `event_name`, `actor`.
- Exceptions are logged *and* re-raised so failures show up in the `Errors` metric; swallowing them would make a broken responder look healthy.
- Sanitization redacts any request parameter whose key looks like a token, secret, password, credential or key, recursively, before anything is written to S3.

## 10. Cost guardrails that are structural, not just promises

- The Lambda's own `PutObject` is an S3 data event. Data events are off, so a report write can never match a rule and trigger a loop.
- Lifecycle expiry means storage can never grow past a few MB.
- No CloudWatch Logs delivery from CloudTrail, no Insights, no data events: the three CloudTrail features that are billed.
- SNS is gated behind `enable_email_alerts`, default `false`.

## 11. Why restore steps also raise incidents

T4 and T5 put the test bucket back the way it was (re-apply the bucket policy, re-enable the public access block). Those restore calls are themselves S3 permission changes, so they correctly produce HIGH incidents too. A real system would suppress or auto-close incidents for approved change windows; this lab keeps them because every permission change should be visible.

## 12. The StopLogging blind spot (observed in testing)

**What happened.** T3 stops the project trail and restarts it one second later. In the first test run the `StopLogging` call produced a CRITICAL incident within 3 seconds. In the second run, with identical commands and timing, EventBridge never delivered the event, so no incident was created, even though CloudTrail Event history recorded the call both times.

**Why.** The EventBridge user guide says that to receive events with a CloudTrail detail-type, "you must enable a CloudTrail trail with logging." T3 turns off the account's only trail, so whether the `StopLogging` call itself still reaches EventBridge is a race against the trail shutting down.

**Why it matters.** This is exactly the attack the CRITICAL rule exists for: an attacker who stops the only trail can also blind the detection of that stop. Detection is best-effort, not guaranteed, in a single-trail account.

**Fixes, and why none is built in.**
- *Scheduled health check.* An EventBridge Scheduler job every few minutes runs a small Lambda that calls `cloudtrail:GetTrailStatus` and writes a CRITICAL incident if `IsLogging` is false. This would likely stay inside the free tier, but it adds a service the spec does not list, so it needs the owner's approval first.
- *A second trail, or an organization trail in a separate account.* Then stopping one trail does not blind EventBridge. A second copy of management events is billed, so it is outside the cost guardrails.
- *Preventive control.* An SCP or IAM deny on `cloudtrail:StopLogging` / `DeleteTrail` for everyone except a break-glass role. This needs AWS Organizations for SCPs.

## 13. Known limitations

- Detection latency depends on CloudTrail → EventBridge delivery. In testing it was 2 to 30 seconds.
- `StopLogging` on the account's only trail is detected only sometimes (see section 12).
- Only management events; no S3 object-level or Lambda data events.
- Single account, single region.
- No automated remediation (for example, automatically re-enabling logging). The report recommends actions; a human applies them. This was deliberate: automated remediation needs broader IAM permissions, which contradicts the least-privilege goal of the responder.
