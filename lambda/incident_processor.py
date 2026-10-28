"""incident-processor Lambda.

Input : an EventBridge event of detail-type "AWS API Call via CloudTrail".
Output: one JSON incident report written to
        s3://<INCIDENT_BUCKET>/incidents/YYYY/MM/DD/<eventID>.json

The CloudTrail eventID is used as the object name, so re-delivery of the same
event overwrites the same object (idempotent). Severity, category and
recommended actions come from the LOOKUP table below, not from Terraform.

Logging is structured JSON on stdout (CloudWatch). Exceptions are logged and
re-raised so failed invocations are visible as errors in CloudWatch metrics.

A second entry point, health_check_handler, is invoked by EventBridge
Scheduler every few minutes. It calls cloudtrail:GetTrailStatus and writes a
CRITICAL incident when the trail is not logging (or no longer exists). This
closes the blind spot found in test T3: stopping the only trail can stop
EventBridge from receiving that same StopLogging event.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.1"  # 1.1: severity_score, score_factors, tactic, remediation

# ---------------------------------------------------------------------------
# Lookup table: event name -> classification
#
# Each entry carries a category, a MITRE ATT&CK tactic, a BASE score (0-100)
# and a generic analyst playbook. The final severity is not fixed here: it is
# computed by score_event() from the base score plus context found in the
# event (root actor, admin policy, public exposure, cross-account trust,
# failed attempt, ...). See docs/severity-scoring.md.
# ---------------------------------------------------------------------------

_IAM_ACTIONS = [
    "Confirm the change was authorised (ticket / change record).",
    "Review the policy document for wildcard (*) actions or resources.",
    "If unauthorised: detach/delete the policy, then rotate the actor's credentials.",
    "Check CloudTrail for other activity by the same principal in the last 24 h.",
]
_LOGGING_ACTIONS = [
    "Re-enable logging immediately: aws cloudtrail start-logging --name <trail>.",
    "Verify trail status with get-trail-status and compare event selectors to the baseline.",
    "Treat as possible defense evasion: review all API activity by the actor since the event.",
    "Consider an SCP or IAM deny on cloudtrail:StopLogging / DeleteTrail for non-admins.",
]
_S3_ACTIONS = [
    "Run aws s3api get-bucket-policy-status to check whether the bucket is now public.",
    "Restore the previous bucket policy / public access block from version control.",
    "Check S3 server access logs or CloudTrail data events (if enabled) for unexpected reads.",
    "Confirm the actor was authorised to change bucket permissions.",
]
_IDENTITY_ACTIONS = [
    "Confirm the new identity or credential was requested (ticket / change record).",
    "If unauthorised: deactivate the new access key or login profile before deleting it, so evidence is kept.",
    "Check what the new identity has done since it was created.",
    "Rotate the credentials of the principal that created it.",
]
_MFA_ACTIONS = [
    "Re-enrol MFA for the affected user and confirm with the user that they removed it.",
    "Treat as possible account takeover: review recent sign-ins and API calls for the user.",
    "Enforce MFA with an IAM policy condition (aws:MultiFactorAuthPresent) for sensitive actions.",
]
_TRUST_ACTIONS = [
    "Compare the role's trust policy with the version in source control.",
    "Check whether any principal outside this account can now assume the role.",
    "If unauthorised: restore the trust policy, then revoke the role's active sessions.",
]
_NETWORK_ACTIONS = [
    "Check whether the rule opens an admin port (22, 3389, databases) to the internet.",
    "If unauthorised: revoke the rule, then review VPC Flow Logs (if enabled) for connections.",
    "Restrict ingress to known CIDR ranges or use Session Manager instead of open SSH/RDP.",
]
_KMS_ACTIONS = [
    "Cancel the key deletion immediately; the key is unrecoverable once the waiting period ends.",
    "Re-enable the key after cancelling (a cancelled key is left Disabled).",
    "Identify what data the key protects and whether anything failed while it was disabled.",
    "Restrict kms:ScheduleKeyDeletion and kms:DisableKey to a break-glass role.",
]


def _entries(names, category, tactic, base, actions, overrides=None):
    overrides = overrides or {}
    return {
        n: {"category": category, "tactic": tactic, "base": overrides.get(n, base), "actions": actions}
        for n in names
    }


LOOKUP: dict[str, dict[str, Any]] = {
    **_entries(
        ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
         "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
         "CreatePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion"),
        "iam_policy_change", "privilege_escalation", 65, _IAM_ACTIONS),
    **_entries(
        ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"),
        "logging_tamper", "defense_evasion", 90, _LOGGING_ACTIONS),
    **_entries(
        # CloudTrail event names (not API names): see terraform/main.tf
        ("PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl",
         "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
         "PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock"),
        "s3_permission_change", "exfiltration", 65, _S3_ACTIONS),
    # --- added 2026-10-28: five new incident types --------------------------
    **_entries(
        ("CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile"),
        "identity_creation", "persistence", 55, _IDENTITY_ACTIONS,
        overrides={"CreateUser": 45}),
    **_entries(
        ("DeactivateMFADevice", "DeleteVirtualMFADevice"),
        "mfa_tampering", "defense_evasion", 75, _MFA_ACTIONS),
    **_entries(
        ("UpdateAssumeRolePolicy",),
        "role_trust_change", "privilege_escalation", 70, _TRUST_ACTIONS),
    **_entries(
        ("AuthorizeSecurityGroupIngress",),
        "network_exposure", "initial_access", 50, _NETWORK_ACTIONS),
    **_entries(
        ("ScheduleKeyDeletion", "DisableKey"),
        "kms_key_destruction", "impact", 85, _KMS_ACTIONS,
        overrides={"DisableKey": 75}),
}

UNCLASSIFIED = {
    "category": "unclassified",
    "tactic": None,
    "base": 40,
    "actions": [
        "This event reached the Lambda but is not in the lookup table.",
        "Review the EventBridge rule pattern and extend LOOKUP if the event is expected.",
    ],
}

# Severity bands for the 0-100 score.
SEVERITY_BANDS = ((85, "CRITICAL"), (60, "HIGH"), (35, "MEDIUM"), (0, "LOW"))


def severity_for(score: int) -> str:
    for floor, name in SEVERITY_BANDS:
        if score >= floor:
            return name
    return "LOW"


for _entry in (*LOOKUP.values(), UNCLASSIFIED):
    _entry["severity"] = severity_for(_entry["base"])  # default severity, before context

# Keys whose values must never be persisted (case-insensitive substring match).
_SENSITIVE_KEY_RE = re.compile(
    r"(token|secret|password|credential|accesskey|privatekey|sessionkey|authorization)",
    re.IGNORECASE,
)
REDACTED = "[REDACTED]"

# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload: dict[str, Any] = {
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "data", None)
        if isinstance(extra, dict):
            payload.update(extra)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class _StdoutHandler(logging.StreamHandler):
    """Resolves sys.stdout at emit time (Lambda and pytest both swap it)."""

    def __init__(self) -> None:
        super().__init__(stream=sys.stdout)

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = sys.stdout
        super().emit(record)


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("incident_processor")
    logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
    logger.propagate = False
    if not logger.handlers:
        handler = _StdoutHandler()
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
    return logger


LOG = _build_logger()


def _log(level: int, message: str, **data: Any) -> None:
    LOG.log(level, message, extra={"data": data})


class NotificationError(RuntimeError):
    """The incident was stored, but the alert could not be sent."""


def notify(topic_arn: str, subject: str, report: dict[str, Any], key: str, request_id: Any) -> None:
    """Publish an alert. The report is already in S3 when this runs.

    On failure we log 'alert_failed' (with the S3 key, so the incident is not
    lost) and raise NotificationError. Raising makes the invocation fail, so
    Lambda's asynchronous retry runs the handler again; the S3 write is
    idempotent (same key), so a retry cannot create a duplicate report.
    Delivery is therefore at-least-once: a retry after a partial failure, or a
    duplicate EventBridge delivery, can send the same alert twice. For
    security alerts a duplicate is preferred over a lost alert.
    """
    try:
        get_client("sns").publish(TopicArn=topic_arn, Subject=subject[:100],
                                  Message=json.dumps(report, indent=2, sort_keys=True))
    except Exception as exc:  # noqa: BLE001 - re-raised as NotificationError
        _log(logging.ERROR, "alert_failed", request_id=request_id, topic_arn=topic_arn,
             incident_id=report.get("incident_id"), s3_key=key,
             error_type=type(exc).__name__, error=str(exc))
        raise NotificationError(f"incident {report.get('incident_id')} stored at {key} but alert failed: {exc}") from exc
    _log(logging.INFO, "alert_published", request_id=request_id, topic_arn=topic_arn,
         incident_id=report.get("incident_id"))


# ---------------------------------------------------------------------------
# AWS clients (indirection so unit tests can inject fakes)
# ---------------------------------------------------------------------------

_CLIENTS: dict[str, Any] = {}


def get_client(service: str) -> Any:
    """Return a cached boto3 client. Tests monkeypatch this function."""
    if service not in _CLIENTS:
        import boto3  # imported lazily so unit tests never need network access

        _CLIENTS[service] = boto3.client(service)
    return _CLIENTS[service]


# ---------------------------------------------------------------------------
# Report building
# ---------------------------------------------------------------------------


def classify(event_name: str | None) -> dict[str, Any]:
    return LOOKUP.get(event_name or "", UNCLASSIFIED)


def sanitize(value: Any, _depth: int = 0) -> Any:
    """Recursively redact values under sensitive-looking keys."""
    if _depth > 20:
        return REDACTED
    if isinstance(value, dict):
        return {
            k: (REDACTED if _SENSITIVE_KEY_RE.search(str(k)) else sanitize(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [sanitize(v, _depth + 1) for v in value]
    return value


def extract_actor(user_identity: dict[str, Any]) -> dict[str, Any]:
    identity_type = user_identity.get("type")
    user_name = user_identity.get("userName")
    if not user_name:
        issuer = (user_identity.get("sessionContext") or {}).get("sessionIssuer") or {}
        user_name = issuer.get("userName")
    if not user_name and identity_type == "Root":
        user_name = "root"
    if not user_name and identity_type == "AssumedRole":
        principal_id = user_identity.get("principalId") or ""
        user_name = principal_id.split(":", 1)[1] if ":" in principal_id else None
    return {
        "type": identity_type,
        "arn": user_identity.get("arn"),
        "user_name": user_name,
    }


_RESOURCE_PARAM_KEYS = {
    "userName": "AWS::IAM::User",
    "roleName": "AWS::IAM::Role",
    "groupName": "AWS::IAM::Group",
    "policyArn": "AWS::IAM::Policy",
    "policyName": "AWS::IAM::Policy",
    "bucketName": "AWS::S3::Bucket",
    "name": "AWS::CloudTrail::Trail",
}


def extract_resources(detail: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for item in detail.get("resources") or []:
        if isinstance(item, dict):
            resources.append(
                {
                    "type": item.get("type"),
                    "identifier": item.get("ARN") or item.get("arn") or item.get("resourceName"),
                }
            )
    params = detail.get("requestParameters") or {}
    if isinstance(params, dict):
        for key, rtype in _RESOURCE_PARAM_KEYS.items():
            if key in params and isinstance(params[key], str):
                resources.append({"type": rtype, "identifier": params[key]})
    return resources


# ---------------------------------------------------------------------------
# Severity scoring
# ---------------------------------------------------------------------------

ADMIN_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
               1433: "SQL Server", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}
_PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}
_ALL_USERS_URI = "acs.amazonaws.com/groups/global/AllUsers"


def _as_json(value: Any) -> Any:
    """CloudTrail sometimes carries policy documents as JSON strings."""
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


def _statements(doc: Any) -> list[dict[str, Any]]:
    doc = _as_json(doc)
    if not isinstance(doc, dict):
        return []
    st = doc.get("Statement", [])
    return [x for x in (st if isinstance(st, list) else [st]) if isinstance(x, dict)]


def _listify(v: Any) -> list[Any]:
    return v if isinstance(v, list) else [v]


def _is_admin_policy(params: dict[str, Any]) -> bool:
    if str(params.get("policyArn", "")).endswith(":policy/AdministratorAccess"):
        return True
    for st in _statements(params.get("policyDocument")):
        if st.get("Effect") == "Allow" and "*" in _listify(st.get("Action")) and "*" in _listify(st.get("Resource")):
            return True
    return False


def _sg_rules(params: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalise AuthorizeSecurityGroupIngress parameters to [{cidr, from, to, proto}]."""
    rules = []
    perms = (params.get("ipPermissions") or {}).get("items", []) if isinstance(params.get("ipPermissions"), dict) else []
    for perm in perms:
        cidrs = [r.get("cidrIp") for r in (perm.get("ipRanges") or {}).get("items", [])]
        cidrs += [r.get("cidrIpv6") for r in (perm.get("ipv6Ranges") or {}).get("items", [])]
        for cidr in cidrs:
            rules.append({"cidr": cidr, "from": perm.get("fromPort"), "to": perm.get("toPort"),
                          "proto": str(perm.get("ipProtocol"))})
    if params.get("cidrIp"):  # older single-rule request shape
        rules.append({"cidr": params["cidrIp"], "from": params.get("fromPort"), "to": params.get("toPort"),
                      "proto": str(params.get("ipProtocol"))})
    return rules


def _exposed_admin_ports(rule: dict[str, Any]) -> list[str]:
    if rule["proto"] in ("-1", "all"):
        return ["all ports"]
    lo, hi = rule.get("from"), rule.get("to")
    if lo is None or hi is None:
        return []
    return [f"{n} ({p})" for p, n in ADMIN_PORTS.items() if int(lo) <= p <= int(hi)]


def _bucket_policy_public(params: dict[str, Any]) -> bool:
    for st in _statements(params.get("bucketPolicy")):
        principal = st.get("Principal")
        public = principal == "*" or (isinstance(principal, dict) and "*" in _listify(principal.get("AWS")))
        if st.get("Effect") == "Allow" and public and not st.get("Condition"):
            return True
    return False


def _trust_principals(params: dict[str, Any]) -> list[str]:
    out = []
    for st in _statements(params.get("policyDocument")):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal")
        if principal == "*":
            out.append("*")
        elif isinstance(principal, dict):
            out += [str(p) for p in _listify(principal.get("AWS", []))]
    return out


def _account_of(principal: str) -> str | None:
    if principal == "*":
        return "*"
    m = re.match(r"^(?:arn:aws[\w-]*:iam::)?(\d{12})(?::|$)", principal)
    return m.group(1) if m else None


def score_event(detail: dict[str, Any], cls: dict[str, Any]) -> tuple[int, list[dict[str, Any]]]:
    """Return (score 0-100, factors). Each factor explains a point change."""
    name = detail.get("eventName")
    params = detail.get("requestParameters") if isinstance(detail.get("requestParameters"), dict) else {}
    identity = detail.get("userIdentity") or {}
    own_account = detail.get("recipientAccountId") or identity.get("accountId")

    factors = [{"factor": f"base score for {cls['category']} ({name})", "points": cls["base"]}]

    def add(points: int, why: str) -> None:
        factors.append({"factor": why, "points": points})

    if identity.get("type") == "Root":
        add(20, "actor is the root user")

    category = cls["category"]
    if category == "iam_policy_change" and _is_admin_policy(params):
        add(20, "grants administrator access (AdministratorAccess or Allow *:*)")
    if category == "network_exposure":
        public = [r for r in _sg_rules(params) if r["cidr"] in _PUBLIC_CIDRS]
        if public:
            add(20, "opens ingress to the whole internet (" + ", ".join(sorted({r["cidr"] for r in public})) + ")")
            ports = sorted({p for r in public for p in _exposed_admin_ports(r)})
            if ports:
                add(10, "exposes admin or database ports: " + ", ".join(ports))
    if category == "s3_permission_change":
        if name == "PutBucketPolicy" and _bucket_policy_public(params):
            add(15, "bucket policy allows anonymous access (Principal *)")
        if name == "PutBucketAcl" and _ALL_USERS_URI in json.dumps(params):
            add(15, "ACL grants access to AllUsers")
        if name == "DeleteAccountPublicAccessBlock":
            add(10, "removes public access protection for every bucket in the account")
    if category == "role_trust_change":
        outsiders = sorted({a for a in map(_account_of, _trust_principals(params)) if a and a != own_account})
        if "*" in outsiders:
            add(30, "trust policy lets ANY AWS principal assume the role")
        elif outsiders:
            add(20, "trust policy now trusts another AWS account: " + ", ".join(outsiders))
    if name == "ScheduleKeyDeletion" and str(params.get("pendingWindowInDays")) == "7":
        add(5, "shortest possible deletion window (7 days)")
    if name in ("CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile"):
        target = params.get("userName")
        if target and target != identity.get("userName"):
            add(10, f"credential created for a different user ({target})")
    if detail.get("errorCode"):
        add(-25, f"call failed ({detail['errorCode']}): an attempt, not a change")

    score = max(0, min(100, sum(f["points"] for f in factors)))
    return score, factors


# ---------------------------------------------------------------------------
# Remediation: concrete, copy-pasteable steps for this specific event
# ---------------------------------------------------------------------------


def _step(step: str, command: str | None = None) -> dict[str, Any]:
    return {"step": step, "command": command}


def build_remediation(detail: dict[str, Any], category: str) -> list[dict[str, Any]]:
    name = detail.get("eventName") or ""
    p = detail.get("requestParameters") if isinstance(detail.get("requestParameters"), dict) else {}
    identity = detail.get("userIdentity") or {}
    user, role, group = p.get("userName", "<user>"), p.get("roleName", "<role>"), p.get("groupName", "<group>")
    arn, pol = p.get("policyArn", "<policy-arn>"), p.get("policyName", "<policy-name>")
    bucket = p.get("bucketName", "<bucket>")
    trail = str(p.get("name", "<trail>")).rsplit("/", 1)[-1]
    steps: list[dict[str, Any]] = []

    if detail.get("errorCode"):
        # Nothing was changed, so there is nothing to roll back.
        return [_step("The call failed, so nothing changed. Investigate why the principal attempted it.",
                      "aws cloudtrail lookup-events --lookup-attributes "
                      f"AttributeKey=Username,AttributeValue={identity.get('userName') or '<user>'}")]

    if category == "iam_policy_change":
        detach = {
            "AttachUserPolicy": f"aws iam detach-user-policy --user-name {user} --policy-arn {arn}",
            "AttachRolePolicy": f"aws iam detach-role-policy --role-name {role} --policy-arn {arn}",
            "AttachGroupPolicy": f"aws iam detach-group-policy --group-name {group} --policy-arn {arn}",
            "PutUserPolicy": f"aws iam delete-user-policy --user-name {user} --policy-name {pol}",
            "PutRolePolicy": f"aws iam delete-role-policy --role-name {role} --policy-name {pol}",
            "PutGroupPolicy": f"aws iam delete-group-policy --group-name {group} --policy-name {pol}",
        }
        if name in detach:
            steps.append(_step("Remove the permission if it was not authorised", detach[name]))
        elif name in ("CreatePolicyVersion", "SetDefaultPolicyVersion"):
            steps.append(_step("List versions and restore the previous default",
                               f"aws iam list-policy-versions --policy-arn {arn}"))
            steps.append(_step("Set the known-good version as default",
                               f"aws iam set-default-policy-version --policy-arn {arn} --version-id <previous-version>"))
        elif name == "CreatePolicy":
            steps.append(_step("Find who the new policy is attached to before deleting it",
                               "aws iam list-entities-for-policy --policy-arn <new-policy-arn>"))
    elif category == "logging_tamper":
        if name == "DeleteTrail":
            steps.append(_step("Recreate the trail from infrastructure as code", "terraform -chdir=terraform apply"))
        else:
            steps.append(_step("Restart logging", f"aws cloudtrail start-logging --name {trail}"))
            steps.append(_step("Confirm the trail is logging", f"aws cloudtrail get-trail-status --name {trail}"))
            steps.append(_step("Compare event selectors with the baseline",
                               f"aws cloudtrail get-event-selectors --trail-name {trail}"))
    elif category == "s3_permission_change":
        if "Account" in name:
            steps.append(_step("Restore the account-level public access block",
                               "aws s3control put-public-access-block --account-id <account-id> "
                               "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                               "BlockPublicPolicy=true,RestrictPublicBuckets=true"))
        else:
            steps.append(_step("Check whether the bucket is now public",
                               f"aws s3api get-bucket-policy-status --bucket {bucket}"))
            steps.append(_step("Re-apply the bucket's public access block",
                               f"aws s3api put-public-access-block --bucket {bucket} "
                               "--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,"
                               "BlockPublicPolicy=true,RestrictPublicBuckets=true"))
            if name == "PutBucketPolicy":
                steps.append(_step("Restore the bucket policy from source control",
                                   f"aws s3api put-bucket-policy --bucket {bucket} --policy file://known-good-policy.json"))
    elif category == "identity_creation":
        if name == "CreateAccessKey":
            key = ((detail.get("responseElements") or {}).get("accessKey") or {}).get("accessKeyId", "<new-access-key-id>")
            steps.append(_step("Deactivate the new access key (keep it for evidence)",
                               f"aws iam update-access-key --user-name {user} --access-key-id {key} --status Inactive"))
        elif name in ("CreateLoginProfile", "UpdateLoginProfile"):
            steps.append(_step("Remove the console password", f"aws iam delete-login-profile --user-name {user}"))
        elif name == "CreateUser":
            steps.append(_step("Check the new user's keys and permissions",
                               f"aws iam list-access-keys --user-name {user}"))
            steps.append(_step("List its attached policies", f"aws iam list-attached-user-policies --user-name {user}"))
    elif category == "mfa_tampering":
        steps.append(_step("List the user's remaining MFA devices", f"aws iam list-mfa-devices --user-name {user}"))
        steps.append(_step(f"Re-enrol MFA for {user} in the console: IAM > Users > {user} > Security credentials"))
    elif category == "role_trust_change":
        steps.append(_step("Inspect the current trust policy",
                           f"aws iam get-role --role-name {role} --query Role.AssumeRolePolicyDocument"))
        steps.append(_step("Restore the trust policy from source control",
                           f"aws iam update-assume-role-policy --role-name {role} --policy-document file://known-good-trust.json"))
        steps.append(_step(f"Revoke active sessions: IAM > Roles > {role} > Revoke sessions"))
    elif category == "network_exposure":
        group_id = p.get("groupId", "<security-group-id>")
        for r in _sg_rules(p):
            if r["cidr"] not in _PUBLIC_CIDRS:
                continue
            all_traffic = r["proto"] in ("-1", "all")
            if ":" in r["cidr"]:  # IPv6 rules need the --ip-permissions form
                ports = "" if all_traffic else f",FromPort={r['from']},ToPort={r['to']}"
                cmd = (f"aws ec2 revoke-security-group-ingress --group-id {group_id} --ip-permissions "
                       f"'IpProtocol={'-1' if all_traffic else r['proto']}{ports},Ipv6Ranges=[{{CidrIpv6={r['cidr']}}}]'")
            else:
                if all_traffic:
                    port = ""
                elif r["from"] == r["to"]:
                    port = f" --port {r['from']}"
                else:
                    port = f" --port {r['from']}-{r['to']}"
                cmd = (f"aws ec2 revoke-security-group-ingress --group-id {group_id} "
                       f"--protocol {'all' if all_traffic else r['proto']}{port} --cidr {r['cidr']}")
            steps.append(_step(f"Revoke the internet-facing rule on {group_id}", cmd))
        if not steps:
            steps.append(_step("Review the new rule", f"aws ec2 describe-security-group-rules --filters Name=group-id,Values={group_id}"))
    elif category == "kms_key_destruction":
        key = p.get("keyId", "<key-id>")
        if name == "ScheduleKeyDeletion":
            steps.append(_step("Cancel the deletion now", f"aws kms cancel-key-deletion --key-id {key}"))
        steps.append(_step("Re-enable the key (a cancelled or disabled key stays Disabled)",
                           f"aws kms enable-key --key-id {key}"))

    # Containment of the actor, when it is a long-term IAM user credential.
    akid = identity.get("accessKeyId", "")
    if identity.get("type") == "IAMUser" and identity.get("userName") and not detail.get("errorCode"):
        steps.append(_step("If the actor's access was not expected, deactivate the key it used",
                           f"aws iam update-access-key --user-name {identity['userName']} "
                           f"--access-key-id {akid or '<access-key-id>'} --status Inactive"))
    elif identity.get("type") == "Root":
        steps.append(_step("Root was used: rotate the root password, confirm root MFA, and delete any root access keys"))
    elif identity.get("type") == "AssumedRole":
        issuer = ((identity.get("sessionContext") or {}).get("sessionIssuer") or {}).get("userName", "<role>")
        steps.append(_step(f"Revoke the role's active sessions: IAM > Roles > {issuer} > Revoke sessions"))
    return steps


def build_report(event: dict[str, Any], detected_at: datetime | None = None) -> dict[str, Any]:
    detail = event.get("detail")
    if not isinstance(detail, dict) or not detail.get("eventID"):
        raise ValueError("event has no CloudTrail detail/eventID; not an 'AWS API Call via CloudTrail' event")

    detected_at = detected_at or datetime.now(timezone.utc)
    event_name = detail.get("eventName")
    cls = classify(event_name)
    user_identity = detail.get("userIdentity") or {}
    score, factors = score_event(detail, cls)

    return {
        "schema_version": SCHEMA_VERSION,
        "incident_id": f"inc-{detail['eventID']}",
        "detected_at": detected_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "event_time": detail.get("eventTime"),
        "severity": severity_for(score),
        "severity_score": score,
        "score_factors": factors,
        "category": cls["category"],
        "tactic": cls["tactic"],
        "event_name": event_name,
        "event_source": detail.get("eventSource"),
        "aws_region": detail.get("awsRegion"),
        "actor": extract_actor(user_identity),
        "source_ip": detail.get("sourceIPAddress"),
        "user_agent": detail.get("userAgent"),
        "resources": extract_resources(detail),
        "request_parameters": sanitize(detail.get("requestParameters")),
        "error_code": detail.get("errorCode"),
        "error_message": detail.get("errorMessage"),
        "recommended_actions": list(cls["actions"]),
        "remediation": build_remediation(detail, cls["category"]),
        "raw_event_id": detail["eventID"],
        "detection_source": "eventbridge",
    }


def incident_key(report: dict[str, Any]) -> str:
    """incidents/YYYY/MM/DD/<eventID>.json, dated by the CloudTrail event time."""
    ts = report.get("event_time") or report["detected_at"]
    day = datetime.strptime(ts[:10], "%Y-%m-%d")
    return f"incidents/{day:%Y/%m/%d}/{report['raw_event_id']}.json"


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


def handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    bucket = os.environ.get("INCIDENT_BUCKET")
    topic_arn = os.environ.get("SNS_TOPIC_ARN") or ""
    request_id = getattr(context, "aws_request_id", None)

    try:
        if not bucket:
            raise RuntimeError("INCIDENT_BUCKET environment variable is not set")

        report = build_report(event)
        key = incident_key(report)
        body = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")

        get_client("s3").put_object(
            Bucket=bucket,
            Key=key,
            Body=body,
            ContentType="application/json",
        )
        _log(
            logging.INFO,
            "incident_written",
            request_id=request_id,
            incident_id=report["incident_id"],
            event_name=report["event_name"],
            severity=report["severity"],
            severity_score=report["severity_score"],
            category=report["category"],
            actor=report["actor"].get("arn"),
            s3_key=key,
            raw_event_id=report["raw_event_id"],
        )

        if topic_arn:
            notify(topic_arn, f"[{report['severity']}] {report['event_name']} detected", report, key, request_id)

        return {"status": "written", "bucket": bucket, "key": key, "incident_id": report["incident_id"]}

    except Exception as exc:  # noqa: BLE001 - we log and re-raise on purpose
        _log(
            logging.ERROR,
            "incident_failed",
            request_id=request_id,
            error_type=type(exc).__name__,
            error=str(exc),
            raw_event_id=((event or {}).get("detail") or {}).get("eventID"),
        )
        LOG.exception("unhandled error in incident_processor")
        raise


# ---------------------------------------------------------------------------
# Scheduled trail health check (EventBridge Scheduler -> this handler)
# ---------------------------------------------------------------------------

_HEALTH_EXTRA_ACTIONS = [
    "Find who stopped or deleted the trail: aws cloudtrail lookup-events "
    "--lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging "
    "(also try DeleteTrail). CloudTrail Event history keeps 90 days even while the trail is off.",
]


def _iso(ts: Any) -> str | None:
    if ts is None:
        return None
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return str(ts)


def _error_code(exc: Exception) -> str | None:
    """botocore ClientError carries the AWS error code in exc.response."""
    response = getattr(exc, "response", None) or {}
    return (response.get("Error") or {}).get("Code")


def build_health_report(
    trail_arn: str,
    problem: str,
    status: dict[str, Any] | None,
    detected_at: datetime | None = None,
) -> dict[str, Any]:
    """problem is 'TrailNotLogging' or 'TrailMissing' (synthetic event names)."""
    detected_at = detected_at or datetime.now(timezone.utc)
    status = status or {}
    trail_name = trail_arn.rsplit("/", 1)[-1]
    stop_time = status.get("StopLoggingTime")

    # Idempotency: one incident per stop. Repeated checks while the trail stays
    # off overwrite the same object. A missing trail has no stop time, so it is
    # keyed per UTC hour instead.
    if stop_time is not None:
        anchor = _iso(stop_time)
        suffix = str(int((stop_time if isinstance(stop_time, datetime) else detected_at).timestamp()))
    else:
        anchor = _iso(detected_at)
        suffix = detected_at.strftime("%Y%m%dT%H")
    incident_ref = f"trail-health-{trail_name}-{problem}-{suffix}"

    return {
        "schema_version": SCHEMA_VERSION,
        "incident_id": f"inc-{incident_ref}",
        "detected_at": _iso(detected_at),
        "event_time": anchor,
        "severity": "CRITICAL",
        "severity_score": 95,
        "score_factors": [{"factor": f"direct status check: {problem} (cannot be hidden by stopping the trail)",
                           "points": 95}],
        "category": "logging_tamper",
        "tactic": "defense_evasion",
        "event_name": problem,
        "event_source": "aws-sec-ir.trail-health-check",
        "aws_region": os.environ.get("AWS_REGION"),
        # GetTrailStatus does not say who stopped the trail; see recommended actions.
        "actor": {"type": None, "arn": None, "user_name": None},
        "source_ip": None,
        "user_agent": None,
        "resources": [{"type": "AWS::CloudTrail::Trail", "identifier": trail_arn}],
        "request_parameters": {
            "is_logging": status.get("IsLogging"),
            "stop_logging_time": _iso(stop_time),
            "start_logging_time": _iso(status.get("StartLoggingTime")),
            "latest_delivery_error": status.get("LatestDeliveryError"),
        },
        "error_code": None,
        "error_message": None,
        "recommended_actions": _HEALTH_EXTRA_ACTIONS + list(LOOKUP["StopLogging"]["actions"]),
        "remediation": (
            [_step("Recreate the trail from infrastructure as code", "terraform -chdir=terraform apply")]
            if problem == "TrailMissing" else
            [_step("Restart logging", f"aws cloudtrail start-logging --name {trail_name}"),
             _step("Confirm the trail is logging", f"aws cloudtrail get-trail-status --name {trail_name}")]
        ) + [_step("Find who stopped or deleted it",
                   "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging")],
        "raw_event_id": incident_ref,
        "detection_source": "scheduled_health_check",
    }


def health_check_handler(event: dict[str, Any] | None = None, context: Any = None) -> dict[str, Any]:
    bucket = os.environ.get("INCIDENT_BUCKET")
    trail_arn = os.environ.get("TRAIL_ARN")
    topic_arn = os.environ.get("SNS_TOPIC_ARN") or ""
    request_id = getattr(context, "aws_request_id", None)

    try:
        if not bucket or not trail_arn:
            raise RuntimeError("INCIDENT_BUCKET and TRAIL_ARN environment variables must be set")

        try:
            status = get_client("cloudtrail").get_trail_status(Name=trail_arn)
        except Exception as exc:  # noqa: BLE001 - only TrailNotFound is an incident
            if _error_code(exc) != "TrailNotFoundException":
                raise
            status, problem = None, "TrailMissing"
        else:
            if status.get("IsLogging"):
                _log(logging.INFO, "trail_healthy", request_id=request_id, trail=trail_arn)
                return {"status": "healthy", "trail": trail_arn}
            problem = "TrailNotLogging"

        report = build_health_report(trail_arn, problem, status)
        key = incident_key(report)
        get_client("s3").put_object(
            Bucket=bucket,
            Key=key,
            Body=json.dumps(report, indent=2, sort_keys=True).encode("utf-8"),
            ContentType="application/json",
        )
        _log(
            logging.WARNING,
            "incident_written",
            request_id=request_id,
            incident_id=report["incident_id"],
            event_name=problem,
            severity=report["severity"],
            category=report["category"],
            detection_source="scheduled_health_check",
            s3_key=key,
        )
        if topic_arn:
            notify(topic_arn, f"[CRITICAL] {problem}: {trail_arn.rsplit('/', 1)[-1]}", report, key, request_id)
        return {"status": "incident", "problem": problem, "bucket": bucket, "key": key}

    except Exception as exc:  # noqa: BLE001 - we log and re-raise on purpose
        _log(
            logging.ERROR,
            "health_check_failed",
            request_id=request_id,
            error_type=type(exc).__name__,
            error=str(exc),
            trail=trail_arn,
        )
        LOG.exception("unhandled error in health_check_handler")
        raise
