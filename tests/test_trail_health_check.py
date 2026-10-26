"""Unit tests for the scheduled trail health check. No AWS access required."""

import json
from datetime import datetime, timezone

import pytest

import incident_processor as ip

TRAIL = "arn:aws:cloudtrail:us-east-1:123456789012:trail/aws-sec-ir-trail"
STOP = datetime(2026, 10, 26, 5, 45, 45, tzinfo=timezone.utc)


class FakeS3:
    def __init__(self):
        self.calls = []

    def put_object(self, **kwargs):
        self.calls.append(kwargs)


class FakeSNS:
    def __init__(self):
        self.calls = []

    def publish(self, **kwargs):
        self.calls.append(kwargs)


class TrailNotFound(Exception):
    response = {"Error": {"Code": "TrailNotFoundException", "Message": "Unknown trail"}}


class AccessDenied(Exception):
    response = {"Error": {"Code": "AccessDeniedException", "Message": "nope"}}


class FakeCloudTrail:
    def __init__(self, status=None, exc=None):
        self.status, self.exc, self.calls = status, exc, []

    def get_trail_status(self, Name):
        self.calls.append(Name)
        if self.exc:
            raise self.exc
        return self.status


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("INCIDENT_BUCKET", "unit-test-incident-bucket")
    monkeypatch.setenv("TRAIL_ARN", TRAIL)
    monkeypatch.setenv("SNS_TOPIC_ARN", "")
    monkeypatch.setenv("AWS_REGION", "us-east-1")


def wire(monkeypatch, ct):
    s3, sns = FakeS3(), FakeSNS()
    monkeypatch.setattr(ip, "get_client", lambda svc: {"s3": s3, "sns": sns, "cloudtrail": ct}[svc])
    return s3, sns


def test_healthy_trail_writes_nothing(env, monkeypatch, capsys):
    ct = FakeCloudTrail(status={"IsLogging": True})
    s3, _ = wire(monkeypatch, ct)
    assert ip.health_check_handler({}, None) == {"status": "healthy", "trail": TRAIL}
    assert ct.calls == [TRAIL]
    assert s3.calls == []
    assert '"message": "trail_healthy"' in capsys.readouterr().out


def test_stopped_trail_writes_critical_incident(env, monkeypatch):
    ct = FakeCloudTrail(status={"IsLogging": False, "StopLoggingTime": STOP})
    s3, _ = wire(monkeypatch, ct)
    result = ip.health_check_handler({}, None)

    assert result["status"] == "incident" and result["problem"] == "TrailNotLogging"
    assert len(s3.calls) == 1
    key = s3.calls[0]["Key"]
    assert key == f"incidents/2026/10/26/trail-health-aws-sec-ir-trail-TrailNotLogging-{int(STOP.timestamp())}.json"
    report = json.loads(s3.calls[0]["Body"])
    assert report["severity"] == "CRITICAL"
    assert report["category"] == "logging_tamper"
    assert report["detection_source"] == "scheduled_health_check"
    assert report["event_time"] == "2026-10-26T05:45:45Z"
    assert report["request_parameters"]["is_logging"] is False
    assert any("lookup-events" in a for a in report["recommended_actions"])


def test_repeated_checks_during_one_stop_reuse_the_same_key(env, monkeypatch):
    ct = FakeCloudTrail(status={"IsLogging": False, "StopLoggingTime": STOP})
    s3, _ = wire(monkeypatch, ct)
    ip.health_check_handler({}, None)
    ip.health_check_handler({}, None)
    assert s3.calls[0]["Key"] == s3.calls[1]["Key"]


def test_missing_trail_is_critical(env, monkeypatch):
    s3, _ = wire(monkeypatch, FakeCloudTrail(exc=TrailNotFound()))
    result = ip.health_check_handler({}, None)
    assert result["problem"] == "TrailMissing"
    report = json.loads(s3.calls[0]["Body"])
    assert report["event_name"] == "TrailMissing" and report["severity"] == "CRITICAL"


def test_other_errors_fail_loudly(env, monkeypatch, capsys):
    s3, _ = wire(monkeypatch, FakeCloudTrail(exc=AccessDenied()))
    with pytest.raises(AccessDenied):
        ip.health_check_handler({}, None)
    assert s3.calls == []
    assert '"message": "health_check_failed"' in capsys.readouterr().out


def test_missing_configuration_fails_loudly(env, monkeypatch):
    monkeypatch.delenv("TRAIL_ARN")
    wire(monkeypatch, FakeCloudTrail(status={"IsLogging": True}))
    with pytest.raises(RuntimeError):
        ip.health_check_handler({}, None)


def test_publishes_alert_when_topic_configured(env, monkeypatch):
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:aws-sec-ir-alerts")
    _, sns = wire(monkeypatch, FakeCloudTrail(status={"IsLogging": False, "StopLoggingTime": STOP}))
    ip.health_check_handler({}, None)
    assert sns.calls[0]["Subject"] == "[CRITICAL] TrailNotLogging: aws-sec-ir-trail"


def test_health_report_has_all_schema_fields():
    report = ip.build_health_report(TRAIL, "TrailNotLogging", {"IsLogging": False, "StopLoggingTime": STOP})
    required = {
        "incident_id", "detected_at", "event_time", "severity", "category", "event_name",
        "event_source", "aws_region", "actor", "source_ip", "user_agent", "resources",
        "request_parameters", "error_code", "recommended_actions", "raw_event_id",
    }
    assert required <= set(report)
    assert set(report["actor"]) == {"type", "arn", "user_name"}
