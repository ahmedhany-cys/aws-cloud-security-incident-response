"""Build an incident timeline from CloudTrail records.

Input: a CloudTrail log file ({"Records": [...]}), a plain list of records, or
EventBridge events ({"detail": {...}}). No AWS access is needed: every record
is classified and scored with the same code the Lambda uses.

What it does, in order:
  1. Validate records. Records without eventID, eventTime, eventName or
     eventSource are rejected with a reason instead of crashing the run.
  2. De-duplicate by eventID. Exact repeats are counted; a repeat with
     different content is reported as a conflict (first copy kept).
  3. Sort by eventTime (CloudTrail log files are not guaranteed to be in order).
  4. Classify and score each event (lambda/incident_processor.py).
  5. Find visibility gaps: StopLogging/DeleteTrail without a later
     StartLogging means the trail may have missed events in that window.
  6. Correlate detections into incidents: same actor, consecutive detections
     less than --window minutes apart. Each incident gets a campaign score,
     the attack stages seen, linked identities and merged remediation.

Usage:
  python simulation/timeline.py simulation/scenarios/compromised-build-agent.json \
      --out-json docs/evidence/simulation/timeline.json \
      --out-md   docs/evidence/simulation/timeline.md
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lambda"))

import incident_processor as ip  # noqa: E402

REQUIRED = ("eventID", "eventTime", "eventName", "eventSource")
TACTIC_ORDER = ["initial_access", "persistence", "privilege_escalation", "defense_evasion",
                "exfiltration", "impact"]
GAP_OPENERS = {"StopLogging", "DeleteTrail"}
GAP_CLOSERS = {"StartLogging", "CreateTrail"}


def _parse_time(value: Any) -> datetime:
    t = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _iso(t: datetime | None) -> str | None:
    return t.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z") if t else None


def load_records(path: str | Path) -> list[Any]:
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict) and "Records" in data:
        return list(data["Records"])
    if isinstance(data, list):
        return data
    return [data]


def _unwrap(item: Any) -> Any:
    """Accept raw CloudTrail records and EventBridge envelopes."""
    if isinstance(item, dict) and isinstance(item.get("detail"), dict) and "detail-type" in item:
        return item["detail"]
    return item


def _actor_key(rec: dict[str, Any]) -> str:
    uid = rec.get("userIdentity") or {}
    if uid.get("type") == "AssumedRole":
        issuer = ((uid.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn")
        return issuer or uid.get("arn") or "unknown"
    return uid.get("arn") or uid.get("principalId") or uid.get("type") or "unknown"


def _trail_name(rec: dict[str, Any]) -> str:
    name = str((rec.get("requestParameters") or {}).get("name", "<unknown trail>"))
    return name.rsplit("/", 1)[-1]


def build_timeline(items: list[Any], window_minutes: int = 60,
                   now: datetime | None = None) -> dict[str, Any]:
    rejected: list[dict[str, Any]] = []
    seen: dict[str, dict[str, Any]] = {}
    conflicted: set[str] = set()
    duplicates: dict[str, int] = {}
    conflicts: list[dict[str, Any]] = []

    # 1-2. validate and de-duplicate
    for idx, raw in enumerate(items):
        rec = _unwrap(raw)
        if not isinstance(rec, dict):
            rejected.append({"index": idx, "reason": "record is not a JSON object"})
            continue
        missing = [f for f in REQUIRED if not rec.get(f)]
        if missing:
            rejected.append({"index": idx, "eventID": rec.get("eventID"), "eventName": rec.get("eventName"),
                             "reason": "missing " + ", ".join(missing)})
            continue
        try:
            _parse_time(rec["eventTime"])
        except ValueError:
            rejected.append({"index": idx, "eventID": rec["eventID"], "eventName": rec.get("eventName"),
                             "reason": f"unparseable eventTime {rec['eventTime']!r}"})
            continue
        eid = rec["eventID"]
        if eid in seen:
            if seen[eid] == rec:
                duplicates[eid] = duplicates.get(eid, 0) + 1
            else:
                conflicted.add(eid)
                conflicts.append({"eventID": eid, "eventName": rec.get("eventName"),
                                  "reason": "same eventID with different content; first copy kept, "
                                            "verify against CloudTrail Event history"})
            continue
        seen[eid] = rec

    # 3. sort
    records = sorted(seen.values(), key=lambda r: (_parse_time(r["eventTime"]), r["eventID"]))

    # 4. classify and score
    entries = []
    for rec in records:
        report = ip.build_report({"detail": rec}, detected_at=_parse_time(rec["eventTime"]))
        detection = report["category"] != "unclassified"
        entries.append({
            "time": _iso(_parse_time(rec["eventTime"])),
            "event_id": rec["eventID"],
            "event_name": rec["eventName"],
            "event_source": rec["eventSource"],
            "actor": report["actor"].get("user_name") or report["actor"].get("arn") or "unknown",
            "actor_key": _actor_key(rec),
            "source_ip": rec.get("sourceIPAddress"),
            "read_only": bool(rec.get("readOnly")),
            "kind": "detection" if detection else ("context" if rec.get("readOnly") else "unclassified_change"),
            "category": report["category"] if detection else None,
            "tactic": report["tactic"],
            "severity": report["severity"] if detection else None,
            "severity_score": report["severity_score"] if detection else None,
            "score_factors": report["score_factors"] if detection else [],
            "error_code": rec.get("errorCode"),
            "resources": report["resources"],
            "remediation": report["remediation"] if detection else [],
            "duplicate_deliveries": duplicates.get(rec["eventID"], 0),
            "conflicting_copy": rec["eventID"] in conflicted,
        })

    # 5. visibility gaps
    gaps: list[dict[str, Any]] = []
    open_gaps: dict[str, dict[str, Any]] = {}
    for e, rec in zip(entries, records):
        if e["error_code"]:
            continue
        if e["event_name"] in GAP_OPENERS:
            trail = _trail_name(rec)
            open_gaps.setdefault(trail, {"trail": trail, "from": e["time"], "opened_by": e["event_name"],
                                         "actor": e["actor"], "to": None, "closed_by": None})
        elif e["event_name"] in GAP_CLOSERS:
            trail = _trail_name(rec)
            if trail in open_gaps:
                g = open_gaps.pop(trail)
                g.update(to=e["time"], closed_by=f"{e['event_name']} by {e['actor']}")
                gaps.append(g)
    end_of_data = _parse_time(entries[-1]["time"]) if entries else (now or datetime.now(timezone.utc))
    for g in open_gaps.values():
        g["to"] = None
        g["still_open_at_end_of_data"] = _iso(end_of_data)
        gaps.append(g)
    for g in gaps:
        end = _parse_time(g["to"]) if g["to"] else end_of_data
        g["minutes"] = round((end - _parse_time(g["from"])).total_seconds() / 60, 1)
        g["events_seen_inside"] = sum(1 for e in entries if _parse_time(g["from"]) < _parse_time(e["time"]) < end)
        g["note"] = ("Trail was not logging: events in this window may be missing from the trail's log files. "
                     "Cross-check CloudTrail Event history, which is independent of the trail.")
        if g["to"] is None:
            g["note"] = "Trail was never restarted in this data. " + g["note"]

    # 6. correlate detections into incidents
    incidents: list[dict[str, Any]] = []
    by_actor: dict[str, list[dict[str, Any]]] = {}
    for e in entries:
        if e["kind"] == "detection":
            by_actor.setdefault(e["actor_key"], []).append(e)
    for actor_key, dets in by_actor.items():
        group: list[dict[str, Any]] = []
        for d in dets:
            if group and _parse_time(d["time"]) - _parse_time(group[-1]["time"]) > timedelta(minutes=window_minutes):
                incidents.append(_summarise(actor_key, group, entries))
                group = []
            group.append(d)
        if group:
            incidents.append(_summarise(actor_key, group, entries))
    incidents.sort(key=lambda i: (-i["campaign_score"], i["start"]))
    for n, inc in enumerate(incidents, 1):
        inc["incident"] = f"INC-{n:03d}"

    counts = {
        "records_in": len(items),
        "accepted": len(records),
        "rejected": len(rejected),
        "duplicate_deliveries": sum(duplicates.values()),
        "conflicts": len(conflicts),
        "detections": sum(1 for e in entries if e["kind"] == "detection"),
        "context_events": sum(1 for e in entries if e["kind"] == "context"),
        "unclassified_changes": sum(1 for e in entries if e["kind"] == "unclassified_change"),
        "incidents": len(incidents),
        "visibility_gaps": len(gaps),
    }
    return {"counts": counts, "incidents": incidents, "visibility_gaps": gaps,
            "timeline": entries, "rejected": rejected, "conflicts": conflicts}


def _summarise(actor_key: str, group: list[dict[str, Any]], entries: list[dict[str, Any]]) -> dict[str, Any]:
    tactics = sorted({d["tactic"] for d in group if d["tactic"]},
                     key=lambda t: TACTIC_ORDER.index(t) if t in TACTIC_ORDER else 99)
    successful = [d for d in group if not d["error_code"]]
    max_score = max(d["severity_score"] for d in group)
    # Several attack stages by one actor is worse than any single step.
    bonus = 5 * max(0, len(tactics) - 1)
    campaign = min(100, max_score + bonus)
    created = sorted({r["identifier"] for d in group if d["event_name"] in ("CreateUser", "CreateAccessKey",
                                                                            "CreateLoginProfile")
                      for r in d["resources"] if r.get("type") == "AWS::IAM::User"})
    start, end = _parse_time(group[0]["time"]), _parse_time(group[-1]["time"])
    recon = [e for e in entries if e["actor_key"] == actor_key and e["kind"] == "context"
             and start - timedelta(minutes=30) <= _parse_time(e["time"]) < start]
    remediation, seen_cmds = [], set()
    for d in sorted(group, key=lambda d: -d["severity_score"]):
        for step in d["remediation"]:
            key = step["command"] or step["step"]
            if key not in seen_cmds:
                seen_cmds.add(key)
                remediation.append({**step, "for_event": f"{d['event_name']} at {d['time']}"})
    return {
        "actor": group[0]["actor"],
        "actor_key": actor_key,
        "source_ips": sorted({d["source_ip"] for d in group if d["source_ip"]}),
        "start": _iso(start),
        "end": _iso(end),
        "duration_minutes": round((end - start).total_seconds() / 60, 1),
        "detections": len(group),
        "failed_attempts": len(group) - len(successful),
        "event_ids": [d["event_id"] for d in group],
        "stages": tactics,
        "categories": sorted({d["category"] for d in group}),
        "max_event_score": max_score,
        "campaign_score": campaign,
        "campaign_bonus": bonus,
        "severity": ip.severity_for(campaign),
        "identities_created": created,
        "reconnaissance_before": [f"{e['time']} {e['event_name']}" for e in recon],
        "remediation": remediation,
    }


def _n(count: int, one: str, many: str | None = None) -> str:
    return f"{count} {one if count == 1 else (many or one + 's')}"


def render_markdown(result: dict[str, Any], title: str = "Incident timeline") -> str:
    c = result["counts"]
    out = [f"# {title}", "",
           "Generated by `simulation/timeline.py` from synthetic CloudTrail records. "
           "All accounts, IPs and identities are fictional placeholders.", "",
           "## Input", "",
           "| Records in | Accepted | Rejected | Duplicate deliveries | Conflicts | Detections | Context events | Incidents | Visibility gaps |",
           "|---|---|---|---|---|---|---|---|---|",
           f"| {c['records_in']} | {c['accepted']} | {c['rejected']} | {c['duplicate_deliveries']} | {c['conflicts']} | "
           f"{c['detections']} | {c['context_events']} | {c['incidents']} | {c['visibility_gaps']} |", ""]

    out += ["## Incidents", ""]
    for inc in result["incidents"]:
        out += [f"### {inc['incident']}: {inc['severity']} (campaign score {inc['campaign_score']}) by `{inc['actor']}`", "",
                f"- **Window:** {inc['start']} to {inc['end']} ({inc['duration_minutes']} min), "
                f"{_n(inc['detections'], 'detection')}, {_n(inc['failed_attempts'], 'failed attempt')}",
                f"- **Source IPs:** {', '.join(inc['source_ips']) or 'n/a'}",
                f"- **Attack stages:** {' > '.join(inc['stages']) or 'n/a'}",
                f"- **Score:** highest single event {inc['max_event_score']}, plus {inc['campaign_bonus']} "
                f"for {_n(len(inc['stages']), 'distinct attack stage')}",
                ]
        if inc["identities_created"]:
            out.append(f"- **Identities created (investigate these too):** {', '.join(inc['identities_created'])}")
        if inc["reconnaissance_before"]:
            out.append(f"- **Read-only activity just before:** {'; '.join(inc['reconnaissance_before'])}")
        out += ["", "Remediation, most severe first:", ""]
        for n, step in enumerate(inc["remediation"], 1):
            cmd = f"  \n   `{step['command']}`" if step["command"] else ""
            out.append(f"{n}. {step['step']} ({step['for_event']}){cmd}")
        out.append("")

    out += ["## Visibility gaps", ""]
    if not result["visibility_gaps"]:
        out += ["None.", ""]
    for g in result["visibility_gaps"]:
        to = g["to"] or f"still stopped at end of data ({g['still_open_at_end_of_data']})"
        out += [f"- **{g['trail']}**: {g['from']} to {to} ({g['minutes']} min), opened by {g['opened_by']} "
                f"({g['actor']}), closed by {g['closed_by'] or 'nobody'}. {g['note']}"]
    out.append("")

    out += ["## Timeline", "",
            "| Time (UTC) | Actor | Event | Kind | Category | Severity | Score | Note |",
            "|---|---|---|---|---|---|---|---|"]
    for e in result["timeline"]:
        note = []
        if e["error_code"]:
            note.append(f"failed: {e['error_code']}")
        if e["duplicate_deliveries"]:
            note.append(f"{_n(e['duplicate_deliveries'], 'duplicate delivery', 'duplicate deliveries')} ignored")
        if e["conflicting_copy"]:
            note.append("a conflicting copy was also received")
        for g in result["visibility_gaps"]:
            if e["time"] == g["from"]:
                note.append("trail stopped here")
            if g["to"] and e["time"] == g["to"]:
                note.append("trail restarted here")
        out.append(f"| {e['time']} | {e['actor']} | {e['event_name']} | {e['kind']} | {e['category'] or ''} | "
                   f"{e['severity'] or ''} | {e['severity_score'] if e['severity_score'] is not None else ''} | "
                   f"{'; '.join(note)} |")
    out.append("")

    out += ["## Rejected and conflicting records", ""]
    if not result["rejected"] and not result["conflicts"]:
        out += ["None.", ""]
    for r in result["rejected"]:
        out.append(f"- Record #{r['index']} ({r.get('eventName') or 'unknown event'}): {r['reason']}")
    for r in result["conflicts"]:
        out.append(f"- {r['eventID']} ({r['eventName']}): {r['reason']}")
    out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("--out-json")
    ap.add_argument("--out-md")
    ap.add_argument("--window", type=int, default=60, help="minutes between detections that still count as one incident")
    ap.add_argument("--title", default="Incident timeline")
    args = ap.parse_args(argv)
    result = build_timeline(load_records(args.input), window_minutes=args.window)
    if args.out_json:
        Path(args.out_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out_json).write_text(json.dumps(result, indent=2) + "\n")
    md = render_markdown(result, args.title)
    if args.out_md:
        Path(args.out_md).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out_md).write_text(md)
    if not args.out_md and not args.out_json:
        print(md)
    print(json.dumps(result["counts"]), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
