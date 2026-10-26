# Incident report schema (v1.0)

Every detection produces exactly one JSON object at
`s3://<incident-bucket>/incidents/YYYY/MM/DD/<eventID>.json`. The date comes
from the CloudTrail `eventTime`; the object name is the CloudTrail `eventID`,
so a re-delivered event overwrites the same object instead of creating a
duplicate (idempotent writes).

| Field | Type | Source | Notes |
|---|---|---|---|
| `schema_version` | string | constant | `"1.0"` |
| `incident_id` | string | `"inc-" + detail.eventID` | Stable, unique per CloudTrail event |
| `detected_at` | string (ISO 8601, UTC) | Lambda clock | When the Lambda processed the event |
| `event_time` | string (ISO 8601, UTC) | `detail.eventTime` | When the API call happened |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` | lookup table | See below |
| `category` | string | lookup table | `iam_policy_change`, `logging_tamper`, `s3_permission_change`, `unclassified` |
| `event_name` | string | `detail.eventName` | e.g. `AttachUserPolicy` |
| `event_source` | string | `detail.eventSource` | e.g. `iam.amazonaws.com` |
| `aws_region` | string | `detail.awsRegion` | `us-east-1` for IAM (global) |
| `actor.type` | string | `userIdentity.type` | `IAMUser`, `AssumedRole`, `Root`, ... |
| `actor.arn` | string | `userIdentity.arn` | |
| `actor.user_name` | string | `userIdentity.userName`, else `sessionContext.sessionIssuer.userName`, else role session name, else `root` | |
| `source_ip` | string | `detail.sourceIPAddress` | May be an AWS service name for service-initiated calls |
| `user_agent` | string | `detail.userAgent` | |
| `resources[]` | list of `{type, identifier}` | `detail.resources` + well-known `requestParameters` keys | e.g. `AWS::S3::Bucket`, `AWS::IAM::User`, `AWS::CloudTrail::Trail` |
| `request_parameters` | object | `detail.requestParameters`, **sanitized** | Any key containing token/secret/password/credential/accessKey/privateKey/sessionKey/authorization has its value replaced by `[REDACTED]` (recursive) |
| `error_code` | string or null | `detail.errorCode` | Present for denied/failed attempts, which are still worth an incident |
| `error_message` | string or null | `detail.errorMessage` | |
| `recommended_actions[]` | list of string | lookup table | Analyst playbook for this category |
| `raw_event_id` | string | `detail.eventID` | Use with `aws cloudtrail lookup-events` to fetch the full record. For health-check incidents it is the incident reference instead |
| `detection_source` | `eventbridge` / `scheduled_health_check` | handler | Which path detected it |

## Health-check incidents

The scheduled trail health check writes the same schema with these differences:

- `event_name` is a synthetic name: `TrailNotLogging` (from `GetTrailStatus`, `IsLogging = false`) or `TrailMissing` (`TrailNotFoundException`).
- `event_time` is the trail's `StopLoggingTime`; for a missing trail it is the detection time.
- `actor`, `source_ip` and `user_agent` are null, because `GetTrailStatus` does not say who stopped the trail. The first recommended action shows the `lookup-events` command that finds out.
- `request_parameters` holds the status fields `is_logging`, `stop_logging_time`, `start_logging_time` and `latest_delivery_error`.
- The key is `incidents/YYYY/MM/DD/trail-health-<trail>-<problem>-<stop epoch>.json`, so one stop gives one incident however many checks run.

## Severity table (lookup in `lambda/incident_processor.py`)

| Category | Event names | Severity |
|---|---|---|
| `iam_policy_change` | AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy, PutUserPolicy, PutRolePolicy, PutGroupPolicy, CreatePolicy, CreatePolicyVersion, SetDefaultPolicyVersion | HIGH |
| `logging_tamper` | StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors | CRITICAL |
| `s3_permission_change` | PutBucketPolicy, DeleteBucketPolicy, PutBucketAcl, PutBucketPublicAccessBlock, DeleteBucketPublicAccessBlock, PutAccountPublicAccessBlock, DeleteAccountPublicAccessBlock | HIGH |
| `logging_tamper` (scheduled check) | TrailNotLogging, TrailMissing | CRITICAL |
| `unclassified` | anything else that reaches the Lambda | MEDIUM |

## Example

```json
{
  "schema_version": "1.0",
  "incident_id": "inc-e1000001-0000-4000-8000-000000000001",
  "detected_at": "2026-10-23T10:15:31Z",
  "event_time": "2026-10-23T10:15:28Z",
  "severity": "HIGH",
  "category": "iam_policy_change",
  "event_name": "AttachUserPolicy",
  "event_source": "iam.amazonaws.com",
  "aws_region": "us-east-1",
  "actor": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::123456789012:user/aws-sec-ir-deployer",
    "user_name": "aws-sec-ir-deployer"
  },
  "source_ip": "203.0.113.10",
  "user_agent": "aws-cli/2.36.40 ...",
  "resources": [
    {"type": "AWS::IAM::User", "identifier": "aws-sec-ir-test-user"},
    {"type": "AWS::IAM::Policy", "identifier": "arn:aws:iam::123456789012:policy/aws-sec-ir/aws-sec-ir-test-policy"}
  ],
  "request_parameters": {
    "userName": "aws-sec-ir-test-user",
    "policyArn": "arn:aws:iam::123456789012:policy/aws-sec-ir/aws-sec-ir-test-policy"
  },
  "error_code": null,
  "error_message": null,
  "recommended_actions": [
    "Confirm the change was authorised (ticket / change record).",
    "Review the policy document for wildcard (*) actions or resources.",
    "If unauthorised: detach/delete the policy, then rotate the actor's credentials.",
    "Check CloudTrail for other activity by the same principal in the last 24 h."
  ],
  "raw_event_id": "e1000001-0000-4000-8000-000000000001"
}
```
