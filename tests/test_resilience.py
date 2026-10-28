"""Missing events, duplicate events and failed notifications.

Covers both the Lambda (what happens to one event) and the timeline builder
(what happens to a whole log). No AWS access required."""

import copy
import json
import sys
from pathlib import Path

import pytest

import incident_processor as ip

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "simulation"))
import timeline as tl  # noqa: E402

EVENTS = ROOT / "tests" / "events"
SCENARIO = ROOT / "simulation" / "scenarios" / "compromised-build-agent.json"
TRAIL = "arn:aws:cloudtrail:us-east-1:123456789012:trail/aws-sec-ir-trail"


def load(name):
    return json.loads((EVENTS / name).read_text())


class FakeS3:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def put_object(self, **kw):
        if self.fail:
            raise RuntimeError("simulated S3 outage")
        self.calls.append(kw)


class FakeSNS:
    def __init__(self, failures=0):
        self.calls, self.failures = [], failures

    def publish(self, **kw):
        if self.failures:
            self.failures -= 1
            raise RuntimeError("simulated SNS throttling")
        self.calls.append(kw)


class FakeCloudTrail:
    def get_trail_status(self, Name):
        return {"IsLogging": False}


@pytest.fixture
def wire(monkeypatch):
    def _wire(s3=None, sns=None):
        s3, sns = s3 or FakeS3(), sns or FakeSNS()
        monkeypatch.setattr(ip, "get_client",
                            lambda svc: {"s3": s3, "sns": sns, "cloudtrail": FakeCloudTrail()}[svc])
        monkeypatch.setenv("INCIDENT_BUCKET", "unit-test-bucket")
        monkeypatch.setenv("TRAIL_ARN", TRAIL)
        monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:aws-sec-ir-alerts")
        return s3, sns
    return _wire


# =============================================================================
# Failed notifications
# =============================================================================

def test_failed_notification_keeps_the_incident_and_fails_loudly(wire, capsys):
    s3, sns = wire(sns=FakeSNS(failures=1))
    with pytest.raises(ip.NotificationError) as exc:
        ip.handler(load("stop_logging.json"), None)
    assert len(s3.calls) == 1, "the report must be stored before the alert is attempted"
    key = s3.calls[0]["Key"]
    assert key in str(exc.value)
    logs = [json.loads(line) for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    alert = next(entry for entry in logs if entry["message"] == "alert_failed")
    assert alert["s3_key"] == key and alert["error_type"] == "RuntimeError"
    assert any(entry["message"] == "incident_failed" for entry in logs), "invocation must show as failed"


def test_retry_after_failed_notification_is_idempotent(wire):
    s3, sns = wire(sns=FakeSNS(failures=1))
    event = load("stop_logging.json")
    with pytest.raises(ip.NotificationError):
        ip.handler(event, None)
    result = ip.handler(event, None)  # Lambda async retry delivers the same event again
    assert result["status"] == "written"
    assert s3.calls[0]["Key"] == s3.calls[1]["Key"], "a retry must overwrite, not duplicate, the report"
    assert len(sns.calls) == 1, "the alert is delivered on the retry"


def test_storage_failure_never_sends_an_alert(wire):
    s3, sns = wire(s3=FakeS3(fail=True))
    with pytest.raises(RuntimeError, match="S3 outage"):
        ip.handler(load("stop_logging.json"), None)
    assert sns.calls == [], "never alert about an incident that was not stored"


def test_health_check_failed_notification(wire):
    s3, sns = wire(sns=FakeSNS(failures=1))
    with pytest.raises(ip.NotificationError):
        ip.health_check_handler({}, None)
    assert len(s3.calls) == 1
    assert json.loads(s3.calls[0]["Body"])["event_name"] == "TrailNotLogging"


def test_subject_is_truncated_to_sns_limit(wire):
    _, sns = wire()
    event = load("stop_logging.json")
    event["detail"]["eventName"] = "StopLogging" + "X" * 200
    ip.handler(event, None)
    assert len(sns.calls[0]["Subject"]) <= 100


# =============================================================================
# Duplicate events
# =============================================================================

def test_duplicate_delivery_writes_one_report_and_alerts_at_least_once(wire):
    s3, sns = wire()
    event = load("create_access_key.json")
    ip.handler(event, None)
    ip.handler(copy.deepcopy(event), None)
    assert len({c["Key"] for c in s3.calls}) == 1, "same eventID, same object"
    # Documented trade-off: alerts are at-least-once, never silently dropped.
    assert len(sns.calls) == 2


def test_timeline_counts_and_ignores_exact_duplicates():
    rec = load("deactivate_mfa_device.json")["detail"]
    result = tl.build_timeline([rec, copy.deepcopy(rec), copy.deepcopy(rec)])
    assert result["counts"]["accepted"] == 1
    assert result["counts"]["duplicate_deliveries"] == 2
    assert result["timeline"][0]["duplicate_deliveries"] == 2


def test_timeline_flags_conflicting_duplicates():
    rec = load("deactivate_mfa_device.json")["detail"]
    altered = {**copy.deepcopy(rec), "requestParameters": {"userName": "someone-else"}}
    result = tl.build_timeline([rec, altered])
    assert result["counts"]["conflicts"] == 1
    assert result["timeline"][0]["conflicting_copy"] is True
    assert result["timeline"][0]["resources"][0]["identifier"] == "admin-ops", "first copy kept"


def test_timeline_accepts_eventbridge_envelopes_and_raw_records_together():
    env = load("schedule_key_deletion.json")
    result = tl.build_timeline([env, copy.deepcopy(env["detail"])])
    assert result["counts"]["accepted"] == 1 and result["counts"]["duplicate_deliveries"] == 1


# =============================================================================
# Missing events and missing fields
# =============================================================================

@pytest.mark.parametrize("field", ["eventID", "eventTime", "eventName", "eventSource"])
def test_timeline_rejects_records_missing_required_fields(field):
    rec = copy.deepcopy(load("create_access_key.json")["detail"])
    rec.pop(field)
    result = tl.build_timeline([rec, "not-a-record"])
    assert result["counts"]["accepted"] == 0 and result["counts"]["rejected"] == 2
    assert field in result["rejected"][0]["reason"]
    assert result["rejected"][1]["reason"] == "record is not a JSON object"


def test_timeline_rejects_unparseable_time():
    rec = copy.deepcopy(load("create_access_key.json")["detail"])
    rec["eventTime"] = "yesterday"
    assert "unparseable" in tl.build_timeline([rec])["rejected"][0]["reason"]


def test_lambda_rejects_event_without_detail_or_event_id(wire):
    for bad in ({"detail-type": "AWS API Call via CloudTrail"},
                {"detail-type": "AWS API Call via CloudTrail", "detail": {"eventName": "StopLogging"}}):
        with pytest.raises(ValueError):
            ip.handler(bad, None)


def test_lambda_survives_missing_optional_fields(wire):
    s3, _ = wire()
    event = load("deactivate_mfa_device.json")
    for f in ("userIdentity", "sourceIPAddress", "userAgent", "requestParameters", "eventTime"):
        event["detail"].pop(f)
    result = ip.handler(event, None)
    body = json.loads(s3.calls[0]["Body"])
    assert result["status"] == "written"
    assert body["actor"] == {"type": None, "arn": None, "user_name": None}
    assert body["event_time"] is None and body["severity"] == "HIGH"
    assert body["remediation"], "remediation falls back to placeholders"


def test_visibility_gap_closed():
    result = tl.build_timeline(tl.load_records(SCENARIO))
    (gap,) = result["visibility_gaps"]
    assert (gap["from"], gap["to"], gap["minutes"]) == ("2026-10-27T09:10:00Z", "2026-10-27T09:41:00Z", 31.0)
    assert gap["closed_by"].startswith("StartLogging by security-oncall")


def test_visibility_gap_left_open_is_reported():
    records = [r for r in tl.load_records(SCENARIO)
               if isinstance(r, dict) and r.get("eventName") not in ("StartLogging",)]
    (gap,) = tl.build_timeline(records)["visibility_gaps"]
    assert gap["to"] is None and gap["still_open_at_end_of_data"] == "2026-10-27T14:00:00Z"
    assert gap["note"].startswith("Trail was never restarted")


def test_failed_stop_logging_opens_no_gap():
    rec = copy.deepcopy(load("stop_logging.json")["detail"])
    rec["errorCode"] = "AccessDenied"
    assert tl.build_timeline([rec])["visibility_gaps"] == []


# =============================================================================
# The full synthetic scenario
# =============================================================================

def test_scenario_counts():
    c = tl.build_timeline(tl.load_records(SCENARIO))["counts"]
    assert c == {"records_in": 23, "accepted": 16, "rejected": 3, "duplicate_deliveries": 3, "conflicts": 1,
                 "detections": 10, "context_events": 5, "unclassified_changes": 1, "incidents": 2,
                 "visibility_gaps": 1}


def test_scenario_timeline_is_sorted_despite_shuffled_input():
    times = [e["time"] for e in tl.build_timeline(tl.load_records(SCENARIO))["timeline"]]
    assert times == sorted(times)


def test_scenario_correlates_one_campaign_and_one_root_incident():
    inc1, inc2 = tl.build_timeline(tl.load_records(SCENARIO))["incidents"]
    assert inc1["actor"] == "build-agent" and inc1["severity"] == "CRITICAL"
    assert inc1["stages"] == ["initial_access", "persistence", "privilege_escalation", "defense_evasion", "impact"]
    assert (inc1["max_event_score"], inc1["campaign_bonus"], inc1["campaign_score"]) == (90, 20, 100)
    assert inc1["detections"] == 9 and inc1["failed_attempts"] == 1
    assert inc1["identities_created"] == ["support-backup"]
    assert len(inc1["reconnaissance_before"]) == 3
    assert inc2["actor"] == "root" and inc2["campaign_score"] == 95


def test_window_splits_incidents():
    records = tl.load_records(SCENARIO)
    wide = tl.build_timeline(records, window_minutes=60)["incidents"]
    narrow = tl.build_timeline(records, window_minutes=10)["incidents"]
    assert len(narrow) > len(wide), "the 33-minute pause before ScheduleKeyDeletion splits a 10-minute window"


def test_benign_activity_never_becomes_an_incident():
    result = tl.build_timeline(tl.load_records(SCENARIO))
    actors = {i["actor"] for i in result["incidents"]}
    assert "reporting-user" not in actors and "security-oncall" not in actors


def test_markdown_and_cli(tmp_path):
    out_md, out_json = tmp_path / "t.md", tmp_path / "t.json"
    assert tl.main([str(SCENARIO), "--out-md", str(out_md), "--out-json", str(out_json)]) == 0
    md = out_md.read_text()
    assert "## Visibility gaps" in md and "INC-001: CRITICAL" in md and "missing eventID" in md
    assert json.loads(out_json.read_text())["counts"]["incidents"] == 2


def test_committed_scenario_matches_generator(tmp_path, monkeypatch):
    """The scenario file in git must be exactly what the generator produces."""
    import generate_scenario as gen
    assert json.loads(SCENARIO.read_text()) == json.loads(json.dumps(gen.messy_log()))
