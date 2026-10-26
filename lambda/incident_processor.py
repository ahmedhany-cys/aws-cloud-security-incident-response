"""incident-processor Lambda.

Input : an EventBridge event of detail-type "AWS API Call via CloudTrail".
Output: one JSON incident report written to
        s3://<INCIDENT_BUCKET>/incidents/YYYY/MM/DD/<eventID>.json

The CloudTrail eventID is used as the object name, so re-delivery of the same
event overwrites the same object (idempotent). Severity, category and
recommended actions come from the LOOKUP table below, not from Terraform.

Logging is structured JSON on stdout (CloudWatch). Exceptions are logged and
re-raised so failed invocations are visible as errors in CloudWatch metrics.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Lookup table: event name -> classification
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

LOOKUP: dict[str, dict[str, Any]] = {
    # IAM policy change -> HIGH
    **{
        name: {"category": "iam_policy_change", "severity": "HIGH", "actions": _IAM_ACTIONS}
        for name in (
            "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
            "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
            "CreatePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
        )
    },
    # Logging tamper -> CRITICAL
    **{
        name: {"category": "logging_tamper", "severity": "CRITICAL", "actions": _LOGGING_ACTIONS}
        for name in ("StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors")
    },
    # S3 permission change -> HIGH
    **{
        name: {"category": "s3_permission_change", "severity": "HIGH", "actions": _S3_ACTIONS}
        for name in (
            # CloudTrail event names (not API names): see terraform/main.tf
            "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl",
            "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
            "PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock",
        )
    },
}

UNCLASSIFIED = {
    "category": "unclassified",
    "severity": "MEDIUM",
    "actions": [
        "This event reached the Lambda but is not in the lookup table.",
        "Review the EventBridge rule pattern and extend LOOKUP if the event is expected.",
    ],
}

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


def build_report(event: dict[str, Any], detected_at: datetime | None = None) -> dict[str, Any]:
    detail = event.get("detail")
    if not isinstance(detail, dict) or not detail.get("eventID"):
        raise ValueError("event has no CloudTrail detail/eventID; not an 'AWS API Call via CloudTrail' event")

    detected_at = detected_at or datetime.now(timezone.utc)
    event_name = detail.get("eventName")
    cls = classify(event_name)
    user_identity = detail.get("userIdentity") or {}

    return {
        "schema_version": SCHEMA_VERSION,
        "incident_id": f"inc-{detail['eventID']}",
        "detected_at": detected_at.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "event_time": detail.get("eventTime"),
        "severity": cls["severity"],
        "category": cls["category"],
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
        "raw_event_id": detail["eventID"],
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
            category=report["category"],
            actor=report["actor"].get("arn"),
            s3_key=key,
            raw_event_id=report["raw_event_id"],
        )

        if topic_arn:
            get_client("sns").publish(
                TopicArn=topic_arn,
                Subject=f"[{report['severity']}] {report['event_name']} detected",
                Message=json.dumps(report, indent=2, sort_keys=True),
            )
            _log(logging.INFO, "alert_published", request_id=request_id, topic_arn=topic_arn)

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
