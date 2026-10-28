# Severity scoring and remediation

Every incident report carries a **score from 0 to 100**, the factors that
produced it, and **remediation steps with ready-to-run commands** filled in
with the real resource names from the event. The code is `score_event()` and
`build_remediation()` in `lambda/incident_processor.py`; the timeline builder
uses the same functions.

## Bands

| Score | Severity |
|---|---|
| 85 to 100 | CRITICAL |
| 60 to 84 | HIGH |
| 35 to 59 | MEDIUM |
| 0 to 34 | LOW |

## Base score per event

| Category | Tactic | Events | Base |
|---|---|---|---|
| logging_tamper | defense_evasion | StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors | 90 |
| kms_key_destruction | impact | ScheduleKeyDeletion | 85 |
| kms_key_destruction | impact | DisableKey | 75 |
| mfa_tampering | defense_evasion | DeactivateMFADevice, DeleteVirtualMFADevice | 75 |
| role_trust_change | privilege_escalation | UpdateAssumeRolePolicy | 70 |
| iam_policy_change | privilege_escalation | Attach/Put User/Role/Group Policy, CreatePolicy, CreatePolicyVersion, SetDefaultPolicyVersion | 65 |
| s3_permission_change | exfiltration | PutBucketPolicy, DeleteBucketPolicy, PutBucketAcl, Put/Delete Bucket/Account PublicAccessBlock | 65 |
| identity_creation | persistence | CreateAccessKey, CreateLoginProfile, UpdateLoginProfile | 55 |
| identity_creation | persistence | CreateUser | 45 |
| network_exposure | initial_access | AuthorizeSecurityGroupIngress | 50 |
| unclassified | none | anything else that reaches the Lambda | 40 |

The original three categories keep exactly the severity they had before
scoring was introduced (HIGH, CRITICAL, HIGH).

## Context modifiers

| Condition found in the event | Points |
|---|---|
| Actor is the root user | +20 |
| Policy grants administrator access (`AdministratorAccess`, or `Allow` `*` on `*`) | +20 |
| Security group rule open to `0.0.0.0/0` or `::/0` | +20 |
| ...and it exposes an admin or database port (22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, or all ports) | +10 |
| Bucket policy allows anonymous access (`Principal: *` without a condition) | +15 |
| Bucket ACL grants `AllUsers` | +15 |
| Account-wide public access block removed | +10 |
| Role trust policy trusts another AWS account | +20 |
| Role trust policy trusts any principal (`*`) | +30 |
| KMS deletion with the shortest window (7 days) | +5 |
| Access key or console password created for a different user than the caller | +10 |
| The call failed (`errorCode` present): an attempt, not a change | -25 |

The score is clamped to 0..100. Every report lists the factors, so the number
can always be explained:

```json
"severity_score": 80,
"score_factors": [
  {"factor": "base score for network_exposure (AuthorizeSecurityGroupIngress)", "points": 50},
  {"factor": "opens ingress to the whole internet (0.0.0.0/0)", "points": 20},
  {"factor": "exposes admin or database ports: SSH (22)", "points": 10}
]
```

## Incident (campaign) score in the timeline

The timeline builder groups detections by actor. A group's campaign score is
the highest single event score **plus 5 for every distinct attack stage beyond
the first**, capped at 100. Five stages (initial access, persistence,
privilege escalation, defense evasion, impact) by one actor therefore add 20.
One noisy-but-harmless event never outranks a multi-stage attack.

## Remediation

Each report has two lists:

- `recommended_actions`: the general playbook for the category (unchanged).
- `remediation`: concrete steps for this event, each with a command where one
  exists, for example
  `aws ec2 revoke-security-group-ingress --group-id sg-0a1b2c3d4e5f60718 --protocol tcp --port 22 --cidr 0.0.0.0/0`.

Rules worth knowing:

- **Failed calls** get one step only (investigate the attempt), because nothing changed.
- **Containment of the actor** is added for IAM-user credentials (deactivate the access key it used), root (rotate the password, check MFA, remove root keys) and assumed roles (revoke sessions).
- **KMS:** a cancelled deletion leaves the key *Disabled* (KMS API reference, CancelKeyDeletion), so the steps cancel and then re-enable.
- **Deactivate before delete:** new access keys are set to `Inactive` first, keeping evidence.
- The Lambda never runs these commands. Automated remediation would need much broader permissions than a write-only responder.
