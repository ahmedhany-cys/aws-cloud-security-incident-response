# Screenshot checklist

Eleven screenshots are required. Save each as PNG in `docs/screenshots/` with
the filename below. **Redact the 12-digit account ID** (top-right of the
console, in ARNs, and in bucket policies), any email address, and the console
sign-in name shown in the top-right account menu before the file is committed. Raw, unredacted captures go in `docs/screenshots/raw/`
(gitignored).

| # | Filename | Console path / URL | What must be visible |
|---|---|---|---|
| 1 | `01-terraform-apply.png` | Terminal, not console | The `Apply complete! Resources: N added, 0 changed, 0 destroyed.` line and the outputs |
| 2 | `02-cloudtrail-trail.png` | CloudTrail → Trails → `aws-sec-ir-trail` (https://us-east-1.console.aws.amazon.com/cloudtrailv2/home?region=us-east-1#/trails) | Trail name, status **Logging**, S3 bucket name, management events Read/Write, no data events, no CloudWatch Logs |
| 3 | `03-cloudtrail-event-history.png` | CloudTrail → Event history, filter Event name = `AttachUserPolicy` (or `StopLogging`) | A test event row with event time, user name `aws-sec-ir-deployer`, event source |
| 4 | `04-eventbridge-rules.png` | EventBridge → Rules (default bus) (https://us-east-1.console.aws.amazon.com/events/home?region=us-east-1#/rules) | The three `aws-sec-ir-*` rules, all Enabled |
| 5 | `05-eventbridge-rule-pattern.png` | EventBridge → Rules → `aws-sec-ir-iam-policy-change` → Event pattern | The JSON pattern with source, detail-type and eventName list |
| 6 | `06-lambda-overview.png` | Lambda → Functions → `aws-sec-ir-incident-processor` | Function overview with the EventBridge trigger(s), runtime Python 3.12, 128 MB |
| 7 | `07-lambda-log-detection.png` | CloudWatch → Log groups → `/aws/lambda/aws-sec-ir-incident-processor` → latest stream | A JSON log line with `"message": "incident_written"` and a severity |
| 8 | `08-incident-bucket-objects.png` | S3 → `aws-sec-ir-incident-reports-<suffix>` → `incidents/YYYY/MM/DD/` | Several `<eventID>.json` objects |
| 9 | `09-incident-json.png` | S3 → one incident object → Open (or the terminal `aws s3 cp ... -` output) | The JSON with severity, category, event_name, actor, recommended_actions |
| 10 | `10-s3-block-public-access.png` | S3 → `aws-sec-ir-incident-reports-<suffix>` → Permissions → Block public access | All four options **On** |
| 11 | `11-billing-free-tier.png` | Billing and Cost Management → Free Tier (https://us-east-1.console.aws.amazon.com/billing/home#/freetier) | Free Tier usage table (or the credit balance on the credit-based plan) showing near-zero usage |

## Status (2026-10-26)

All 11 captured by Claude in the built-in browser while the owner was signed in
to the console as their IAM user (not root).

- **#2 to #8, #10, #11:** real console pages.
- **#1 and #9:** terminal output (`terraform apply` and `aws s3 cp` of an incident), rendered to PNG with macOS Quick Look from the real captured output.
- **#3:** shows the T1 test event, because event history had not yet indexed the T3 event at capture time.
- **Later the same day:** the account menu in the top-right corner of #2 to #8, #10 and #11 (sign-in name and first name) was painted over with the navbar colour; nothing else in the images changed. #1 and #9 are terminal renderings and never showed it.
- **#5:** the long `eventName` line runs off the right edge of the console's code box. The full pattern is in `../evidence/06-rule-*.json`.

## Redaction

Redaction was applied before capture. A script replaced every 12-digit
account ID, email address, IPv4 address, access key ID and IAM unique ID in the
page text, so no unredacted image was ever saved. Each capture was checked to
contain zero remaining 12-digit numbers. Manual fallback for future captures:
open the PNG in Preview, use Markup to draw a filled rectangle over the ID,
export it, and keep the original in `raw/`.
