"""Generate synthetic CloudTrail data for offline simulation and tests.

Writes:
  simulation/scenarios/compromised-build-agent.json
      A CloudTrail log file ({"Records": [...]}) telling one attack story,
      deliberately messy: records out of order, duplicate deliveries, one
      conflicting duplicate, three malformed records and a logging gap.
  tests/events/<new type>.json
      EventBridge-shaped sample events for the five new incident types.

Everything is deterministic (fixed times, uuid5 event IDs, seeded shuffle),
so re-running produces identical files. All identifiers are placeholders:
account 123456789012 (this account), 111122223333 (an outside account, the
AWS documentation example), IPs from the RFC 5737 documentation ranges, and
access key IDs that cannot be real (too short to match the AKIA format).

The story (2026-10-27, UTC), all by the IAM user "build-agent" whose access
key leaked, from 198.51.100.23:
  09:00 reconnaissance (GetCallerIdentity, ListUsers, ListAttachedUserPolicies)
  09:03 CreateUser support-backup, then CreateAccessKey for it (persistence)
  09:04 AttachUserPolicy AdministratorAccess to support-backup
  09:04 PutRolePolicy on prod-deploy-role, which FAILS (AccessDenied)
  09:06 UpdateAssumeRolePolicy: prod-deploy-role now trusts 111122223333
  09:07 DeactivateMFADevice for admin-ops
  09:08 AuthorizeSecurityGroupIngress: SSH open to 0.0.0.0/0
  09:10 StopLogging on the trail (delivered three times)
  09:41 security-oncall restarts logging (StartLogging)
  09:43 ScheduleKeyDeletion on the data key, 7-day window
  14:00 the root user disables another KMS key (a separate incident)
"""

from __future__ import annotations

import json
import random
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = "123456789012"
OUTSIDE_ACCOUNT = "111122223333"
REGION = "us-east-1"
ATTACKER_IP = "198.51.100.23"
OFFICE_IP = "203.0.113.10"
ONCALL_IP = "192.0.2.44"
ROOT_IP = "203.0.113.77"
DAY = "2026-10-27"
NS = uuid.UUID("6f1c2a5e-0000-4000-8000-0000000a5e1c")
DATA_KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/1a2b3c4d-1111-4a4a-8b8b-0c0c0c0c0c01"
BACKUP_KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/1a2b3c4d-2222-4a4a-8b8b-0c0c0c0c0c02"
TRAIL_ARN = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/aws-sec-ir-trail"

SOURCES = {"iam": "iam.amazonaws.com", "sts": "sts.amazonaws.com", "ec2": "ec2.amazonaws.com",
           "kms": "kms.amazonaws.com", "s3": "s3.amazonaws.com", "cloudtrail": "cloudtrail.amazonaws.com"}


def iam_user(name: str, key: str) -> dict:
    return {"type": "IAMUser", "principalId": f"AIDAEXAMPLE{name.upper().replace('-', '')}"[:21],
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}", "accountId": ACCOUNT,
            "accessKeyId": key, "userName": name}


BUILD_AGENT = iam_user("build-agent", "AKIASYNTHETIC0001")
REPORTING = iam_user("reporting-user", "AKIASYNTHETIC0007")
ONCALL = iam_user("security-oncall", "AKIASYNTHETIC0009")
ROOT_USER = {"type": "Root", "principalId": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:root",
             "accountId": ACCOUNT}


def rec(time: str, svc: str, name: str, who: dict, ip: str, params=None, *, read_only=False,
        response=None, error=None, resources=None, seq: str | None = None) -> dict:
    r = {
        "eventVersion": "1.11",
        "userIdentity": who,
        "eventTime": f"{DAY}T{time}Z",
        "eventSource": SOURCES[svc],
        "eventName": name,
        "awsRegion": REGION,
        "sourceIPAddress": ip,
        "userAgent": "aws-cli/2.36.40 md/command#synthetic" if who.get("type") != "Root" else "console.amazonaws.com",
        "requestParameters": params,
        "responseElements": response,
        "requestID": str(uuid.uuid5(NS, f"req-{time}-{name}")),
        "eventID": str(uuid.uuid5(NS, seq or f"{time}-{name}")),
        "readOnly": read_only,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": ACCOUNT,
        "eventCategory": "Management",
    }
    if error:
        r["errorCode"], r["errorMessage"] = error
    if resources:
        r["resources"] = resources
    return r


def trust_policy(principal: str) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"},
        {"Effect": "Allow", "Principal": {"AWS": principal}, "Action": "sts:AssumeRole"}]})


def story() -> list[dict]:
    R = []
    R.append(rec("08:55:12", "ec2", "DescribeInstances", REPORTING, OFFICE_IP, {"maxResults": 50}, read_only=True))
    R.append(rec("09:00:05", "sts", "GetCallerIdentity", BUILD_AGENT, ATTACKER_IP, None, read_only=True))
    R.append(rec("09:01:10", "iam", "ListUsers", BUILD_AGENT, ATTACKER_IP, {"maxItems": 100}, read_only=True))
    R.append(rec("09:01:40", "iam", "ListAttachedUserPolicies", BUILD_AGENT, ATTACKER_IP,
                 {"userName": "build-agent"}, read_only=True))
    R.append(rec("09:03:00", "iam", "CreateUser", BUILD_AGENT, ATTACKER_IP, {"userName": "support-backup"},
                 response={"user": {"userName": "support-backup", "path": "/",
                                    "arn": f"arn:aws:iam::{ACCOUNT}:user/support-backup"}}))
    R.append(rec("09:03:20", "iam", "CreateAccessKey", BUILD_AGENT, ATTACKER_IP, {"userName": "support-backup"},
                 response={"accessKey": {"userName": "support-backup", "accessKeyId": "AKIASYNTHETIC0002",
                                         "status": "Active"}}))
    R.append(rec("09:04:00", "iam", "AttachUserPolicy", BUILD_AGENT, ATTACKER_IP,
                 {"userName": "support-backup", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}))
    R.append(rec("09:04:30", "iam", "PutRolePolicy", BUILD_AGENT, ATTACKER_IP,
                 {"roleName": "prod-deploy-role", "policyName": "maintenance",
                  "policyDocument": json.dumps({"Version": "2012-10-17", "Statement": [
                      {"Effect": "Allow", "Action": "*", "Resource": "*"}]})},
                 error=("AccessDenied", "User: build-agent is not authorized to perform: iam:PutRolePolicy")))
    R.append(rec("09:06:00", "iam", "UpdateAssumeRolePolicy", BUILD_AGENT, ATTACKER_IP,
                 {"roleName": "prod-deploy-role",
                  "policyDocument": trust_policy(f"arn:aws:iam::{OUTSIDE_ACCOUNT}:root")}))
    R.append(rec("09:07:30", "iam", "DeactivateMFADevice", BUILD_AGENT, ATTACKER_IP,
                 {"userName": "admin-ops", "serialNumber": f"arn:aws:iam::{ACCOUNT}:mfa/admin-ops"}))
    R.append(rec("09:08:15", "ec2", "AuthorizeSecurityGroupIngress", BUILD_AGENT, ATTACKER_IP,
                 {"groupId": "sg-0a1b2c3d4e5f60718", "ipPermissions": {"items": [
                     {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "groups": {},
                      "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}, "ipv6Ranges": {}, "prefixListIds": {}}]}},
                 response={"_return": True}))
    R.append(rec("09:10:00", "cloudtrail", "StopLogging", BUILD_AGENT, ATTACKER_IP, {"name": TRAIL_ARN},
                 resources=[{"type": "AWS::CloudTrail::Trail", "ARN": TRAIL_ARN}]))
    R.append(rec("09:41:00", "cloudtrail", "StartLogging", ONCALL, ONCALL_IP, {"name": TRAIL_ARN},
                 resources=[{"type": "AWS::CloudTrail::Trail", "ARN": TRAIL_ARN}]))
    R.append(rec("09:43:00", "kms", "ScheduleKeyDeletion", BUILD_AGENT, ATTACKER_IP,
                 {"keyId": DATA_KEY, "pendingWindowInDays": 7},
                 response={"keyId": DATA_KEY, "deletionDate": "Nov 3, 2026, 12:00:00 AM", "keyState": "PendingDeletion"},
                 resources=[{"type": "AWS::KMS::Key", "ARN": DATA_KEY}]))
    R.append(rec("09:45:30", "s3", "ListBuckets", REPORTING, OFFICE_IP, {"Host": "s3.amazonaws.com"}, read_only=True))
    R.append(rec("14:00:00", "kms", "DisableKey", ROOT_USER, ROOT_IP, {"keyId": BACKUP_KEY},
                 resources=[{"type": "AWS::KMS::Key", "ARN": BACKUP_KEY}]))
    return R


def messy_log() -> dict:
    records = story()
    by_name = {r["eventName"]: r for r in records}
    extra = [
        # duplicate deliveries (identical copies)
        dict(by_name["StopLogging"]), dict(by_name["StopLogging"]), dict(by_name["CreateAccessKey"]),
        # malformed records
        {k: v for k, v in rec("09:20:00", "s3", "PutBucketPolicy", REPORTING, OFFICE_IP,
                               {"bucketName": "reports-bucket"}).items() if k != "eventTime"},
        {k: v for k, v in rec("09:25:00", "cloudtrail", "DeleteTrail", BUILD_AGENT, ATTACKER_IP,
                               {"name": TRAIL_ARN}).items() if k != "eventID"},
        {**rec("09:30:00", "iam", "CreateAccessKey", BUILD_AGENT, ATTACKER_IP, {"userName": "support-backup"},
               seq="bad-time"), "eventTime": "yesterday"},
    ]
    all_records = records + extra
    random.Random(7).shuffle(all_records)
    # A conflicting copy (same eventID, altered content) arrives after the
    # original, as a tampered or corrupted re-delivery would.
    all_records.append({**by_name["CreateUser"], "requestParameters": {"userName": "someone-else"}})
    return {"Records": all_records}


def eventbridge(r: dict, rule: str) -> dict:
    svc = r["eventSource"].split(".")[0]
    return {"version": "0", "id": str(uuid.uuid5(NS, "eb-" + r["eventID"])),
            "detail-type": "AWS API Call via CloudTrail", "source": f"aws.{svc}", "account": ACCOUNT,
            "time": r["eventTime"], "region": REGION, "resources": [], "detail": r,
            "_comment": f"synthetic event matching the aws-sec-ir-{rule} rule"}


SAMPLE_EVENTS = {
    "create_access_key.json": ("CreateAccessKey", "identity-creation"),
    "deactivate_mfa_device.json": ("DeactivateMFADevice", "mfa-tampering"),
    "update_assume_role_policy.json": ("UpdateAssumeRolePolicy", "role-trust-change"),
    "authorize_sg_ingress.json": ("AuthorizeSecurityGroupIngress", "network-exposure"),
    "schedule_key_deletion.json": ("ScheduleKeyDeletion", "kms-key-destruction"),
}


def main() -> None:
    out = ROOT / "simulation" / "scenarios" / "compromised-build-agent.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(messy_log(), indent=2) + "\n")
    by_name = {r["eventName"]: r for r in story()}
    for fname, (event, rule) in SAMPLE_EVENTS.items():
        (ROOT / "tests" / "events" / fname).write_text(json.dumps(eventbridge(by_name[event], rule), indent=2) + "\n")
    print(f"wrote {out.relative_to(ROOT)} and {len(SAMPLE_EVENTS)} sample events in tests/events/")


if __name__ == "__main__":
    main()
