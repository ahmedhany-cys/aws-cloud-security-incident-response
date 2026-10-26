"""Unit tests for lambda/incident_processor.py. No AWS access required."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import incident_processor as ip

EVENTS = Path(__file__).parent / "events"


def load(name: str) -> dict:
    return json.loads((EVENTS / name).read_text())


class FakeS3:
    def __init__(self):
        self.calls = []

    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        return {"ETag": "fake"}


class FakeSNS:
    def __init__(self):
        self.calls = []

    def publish(self, **kwargs):
        self.calls.append(kwargs)
        return {"MessageId": "fake"}


class FailingS3:
    def put_object(self, **kwargs):
        raise RuntimeError("simulated S3 failure")


@pytest.fixture
def fake_clients(monkeypatch):
    s3, sns = FakeS3(), FakeSNS()
    monkeypatch.setattr(ip, "get_client", lambda svc: {"s3": s3, "sns": sns}[svc])
    monkeypatch.setenv("INCIDENT_BUCKET", "unit-test-incident-bucket")
    monkeypatch.setenv("SNS_TOPIC_ARN", "")
    return s3, sns


# --- classification ----------------------------------------------------------

@pytest.mark.parametrize(
    "event_file,expected_name,expected_severity,expected_category",
    [
        ("attach_user_policy.json", "AttachUserPolicy", "HIGH", "iam_policy_change"),
        ("put_user_policy.json", "PutUserPolicy", "HIGH", "iam_policy_change"),
        ("stop_logging.json", "StopLogging", "CRITICAL", "logging_tamper"),
        ("put_bucket_policy.json", "PutBucketPolicy", "HIGH", "s3_permission_change"),
        ("delete_public_access_block.json", "DeleteBucketPublicAccessBlock", "HIGH", "s3_permission_change"),
    ],
)
def test_report_classification(event_file, expected_name, expected_severity, expected_category):
    report = ip.build_report(load(event_file))
    assert report["event_name"] == expected_name
    assert report["severity"] == expected_severity
    assert report["category"] == expected_category
    assert report["recommended_actions"], "every classified event must carry recommended actions"


def test_every_rule_event_name_is_in_lookup():
    """The Terraform rule lists and the Lambda lookup table must agree."""
    tf = (Path(__file__).parents[1] / "terraform" / "main.tf").read_text()
    import re
    names = set(re.findall(r'"([A-Z][A-Za-z]+)"', tf.split("detection_rules")[1]))
    names -= {"AWS"}  # not an event name
    missing = names - set(ip.LOOKUP)
    assert not missing, f"event names in Terraform but not in LOOKUP: {missing}"


def test_api_names_that_cloudtrail_never_emits_are_not_used():
    """Regression for T5 attempt 1: S3 logs PublicAccessBlock calls under
    different CloudTrail event names than the API operation names."""
    tf = (Path(__file__).parents[1] / "terraform" / "main.tf").read_text()
    for api_only in ('"PutPublicAccessBlock"', '"DeletePublicAccessBlock"'):
        assert api_only not in tf
        assert api_only.strip('"') not in ip.LOOKUP
    for ct_name in ("PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
                    "PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock"):
        assert ct_name in ip.LOOKUP


def test_unknown_event_is_unclassified_but_still_reported():
    report = ip.build_report(load("benign_list_users.json"))
    assert report["category"] == "unclassified"
    assert report["severity"] == "MEDIUM"


# --- schema ------------------------------------------------------------------

REQUIRED_FIELDS = {
    "incident_id", "detected_at", "event_time", "severity", "category", "event_name",
    "event_source", "aws_region", "actor", "source_ip", "user_agent", "resources",
    "request_parameters", "error_code", "recommended_actions", "raw_event_id",
}


def test_report_has_all_schema_fields():
    report = ip.build_report(load("attach_user_policy.json"))
    assert REQUIRED_FIELDS <= set(report)
    assert set(report["actor"]) == {"type", "arn", "user_name"}
    assert report["incident_id"] == "inc-e1000001-0000-4000-8000-000000000001"
    assert report["raw_event_id"] == "e1000001-0000-4000-8000-000000000001"
    assert report["detection_source"] == "eventbridge"


def test_detected_at_is_utc_iso():
    fixed = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
    report = ip.build_report(load("attach_user_policy.json"), detected_at=fixed)
    assert report["detected_at"] == "2026-10-23T12:00:00Z"


def test_resources_extracted_from_request_parameters_and_resources():
    report = ip.build_report(load("put_bucket_policy.json"))
    identifiers = {r["identifier"] for r in report["resources"]}
    assert "aws-sec-ir-test-bucket-abc1234" in identifiers
    assert "arn:aws:s3:::aws-sec-ir-test-bucket-abc1234" in identifiers

    report = ip.build_report(load("attach_user_policy.json"))
    assert {"type": "AWS::IAM::User", "identifier": "aws-sec-ir-test-user"} in report["resources"]


# --- actor -------------------------------------------------------------------

def test_iam_user_actor():
    actor = ip.build_report(load("attach_user_policy.json"))["actor"]
    assert actor == {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789012:user/aws-sec-ir-deployer",
        "user_name": "aws-sec-ir-deployer",
    }


def test_assumed_role_actor_uses_session_issuer():
    actor = ip.build_report(load("assumed_role_with_secrets.json"))["actor"]
    assert actor["type"] == "AssumedRole"
    assert actor["user_name"] == "AdminRole"


def test_root_actor():
    assert ip.extract_actor({"type": "Root", "arn": "arn:aws:iam::123456789012:root"})["user_name"] == "root"


# --- sanitization ------------------------------------------------------------

def test_sensitive_request_parameters_are_redacted():
    report = ip.build_report(load("assumed_role_with_secrets.json"))
    params = report["request_parameters"]
    assert params["sessionToken"] == ip.REDACTED
    assert params["nested"]["clientSecret"] == ip.REDACTED
    assert params["nested"]["list"][0]["password"] == ip.REDACTED
    assert params["nested"]["harmless"] == "keep-me"
    assert params["policyArn"] == "arn:aws:iam::123456789012:policy/SomePolicy"
    assert "FwoGZXIvYXdz" not in json.dumps(report)


def test_error_code_is_preserved():
    report = ip.build_report(load("assumed_role_with_secrets.json"))
    assert report["error_code"] == "AccessDenied"


# --- key / idempotency -------------------------------------------------------

def test_incident_key_uses_event_time_date_and_event_id():
    report = ip.build_report(load("stop_logging.json"))
    assert ip.incident_key(report) == "incidents/2026/10/23/e1000003-0000-4000-8000-000000000003.json"


def test_same_event_twice_writes_same_key(fake_clients):
    s3, _ = fake_clients
    ip.handler(load("attach_user_policy.json"), None)
    ip.handler(load("attach_user_policy.json"), None)
    assert len(s3.calls) == 2
    assert s3.calls[0]["Key"] == s3.calls[1]["Key"]


# --- handler -----------------------------------------------------------------

def test_handler_writes_json_to_incident_bucket(fake_clients):
    s3, sns = fake_clients
    result = ip.handler(load("attach_user_policy.json"), None)

    assert result["status"] == "written"
    assert len(s3.calls) == 1
    call = s3.calls[0]
    assert call["Bucket"] == "unit-test-incident-bucket"
    assert call["Key"].startswith("incidents/2026/10/23/")
    assert call["ContentType"] == "application/json"
    body = json.loads(call["Body"])
    assert body["event_name"] == "AttachUserPolicy"
    assert sns.calls == []  # alerts are off by default


def test_handler_publishes_to_sns_when_topic_configured(fake_clients, monkeypatch):
    _, sns = fake_clients
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:aws-sec-ir-alerts")
    ip.handler(load("stop_logging.json"), None)
    assert len(sns.calls) == 1
    assert sns.calls[0]["Subject"] == "[CRITICAL] StopLogging detected"


def test_handler_rejects_non_cloudtrail_event(fake_clients):
    with pytest.raises(ValueError):
        ip.handler({"detail-type": "Scheduled Event", "detail": {}}, None)


def test_handler_fails_loudly_without_bucket(fake_clients, monkeypatch):
    monkeypatch.delenv("INCIDENT_BUCKET")
    with pytest.raises(RuntimeError):
        ip.handler(load("attach_user_policy.json"), None)


def test_handler_reraises_s3_errors(monkeypatch, capsys):
    monkeypatch.setattr(ip, "get_client", lambda svc: FailingS3())
    monkeypatch.setenv("INCIDENT_BUCKET", "b")
    with pytest.raises(RuntimeError, match="simulated S3 failure"):
        ip.handler(load("attach_user_policy.json"), None)
    out = capsys.readouterr().out
    assert '"message": "incident_failed"' in out
    assert '"error_type": "RuntimeError"' in out


def test_logs_are_json_lines(fake_clients, capsys):
    ip.handler(load("put_user_policy.json"), None)
    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]
    assert lines, "handler must log"
    parsed = json.loads(lines[-1])
    assert parsed["message"] == "incident_written"
    assert parsed["severity"] == "HIGH"
