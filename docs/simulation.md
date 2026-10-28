# Simulation and incident timeline

The five incident types added on 2026-10-28 cannot be triggered safely in the
live account: creating access keys or console passwords is forbidden by the
project rules, and MFA, security groups and KMS keys are outside the project's
resources. They are therefore exercised with **synthetic CloudTrail data**,
using exactly the same classification, scoring and remediation code as the
deployed Lambda. Nothing in this folder needs AWS access.

## Files

| File | Purpose |
|---|---|
| `simulation/generate_scenario.py` | Writes the synthetic CloudTrail log and the five sample EventBridge events (deterministic) |
| `simulation/scenarios/compromised-build-agent.json` | The generated log: one attack story plus deliberately messy data |
| `simulation/timeline.py` | Builds an incident timeline from any CloudTrail log file, record list or EventBridge events |
| `docs/evidence/simulation/timeline.md` and `.json` | The timeline produced from the scenario |

```bash
.venv/bin/python simulation/generate_scenario.py
.venv/bin/python simulation/timeline.py simulation/scenarios/compromised-build-agent.json \
  --out-md docs/evidence/simulation/timeline.md --out-json docs/evidence/simulation/timeline.json
```

The timeline tool also works on real CloudTrail log files downloaded from the
audit bucket (after `gunzip`).

## The scenario

The access key of the IAM user `build-agent` has leaked. From one IP address
the attacker does reconnaissance, creates a backdoor user with an access key,
gives it AdministratorAccess, fails to add an inline policy to a role, makes
the role trust an outside account, removes another user's MFA, opens SSH to
the internet, stops CloudTrail, and after the on-call engineer restarts it,
schedules a KMS key for deletion. Later, the root user disables another key.

The data is deliberately messy, the way real log data is:

| Problem | In the scenario | How the timeline handles it |
|---|---|---|
| Out-of-order records | the whole file is shuffled | sorted by `eventTime` |
| Duplicate deliveries | StopLogging x3, CreateAccessKey x2 | counted, kept once |
| Conflicting duplicate | CreateUser re-delivered with a different user name | first copy kept, flagged for verification |
| Missing fields | one record without `eventTime`, one without `eventID` | rejected with the reason |
| Bad timestamp | `"eventTime": "yesterday"` | rejected with the reason |
| Missing events | trail stopped 09:10 to 09:41 | reported as a 31-minute visibility gap |
| Benign noise | read-only calls by other users | shown as context, never an incident |

## Result

See [the generated timeline](evidence/simulation/timeline.md). In short:

- **INC-001, CRITICAL, campaign score 100**, `build-agent`, 40 minutes, 9 detections (1 failed), all five attack stages, backdoor identity `support-backup`, 3 reconnaissance calls just before.
- **INC-002, CRITICAL, score 95**, root disabled a KMS key.
- **One visibility gap** of 31 minutes while the trail was stopped.
- 23 records in, 16 accepted, 3 rejected, 3 duplicate deliveries, 1 conflict.

## Notification semantics (failed and duplicate alerts)

The Lambda stores the report in S3 **before** sending an alert.

- **Alert fails:** the error is logged as `alert_failed` with the report's S3 key, and the invocation fails with `NotificationError`. Lambda's asynchronous retry runs it again; the S3 write is idempotent (same key), so the retry cannot create a second report, and the alert is sent on the retry.
- **Storage fails:** no alert is sent. The responder never alerts about an incident it did not store.
- **Duplicate event:** one report (same key), but the alert may be sent twice. Alerts are at-least-once on purpose: for security alerts a duplicate is better than a lost alert.
