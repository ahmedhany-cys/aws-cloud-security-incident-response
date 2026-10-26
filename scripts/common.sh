#!/usr/bin/env bash
# Shared helpers for the test and evidence scripts. Sourced, not executed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$REPO_ROOT/terraform"
EVIDENCE_RAW="$REPO_ROOT/docs/evidence/raw"
EVIDENCE_DIR="$REPO_ROOT/docs/evidence"
REDACT="$REPO_ROOT/scripts/redact.sh"

export AWS_PROFILE="${AWS_PROFILE:-sec-ir}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_PAGER=""

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }

tf_out() { terraform -chdir="$TF_DIR" output -raw "$1"; }

load_outputs() {
  INCIDENT_BUCKET="$(tf_out incident_bucket)"
  TEST_BUCKET="$(tf_out test_bucket)"
  TEST_USER="$(tf_out test_user_name)"
  TEST_POLICY_ARN="$(tf_out test_policy_arn)"
  TRAIL_NAME="$(tf_out trail_name)"
  LAMBDA_NAME="$(tf_out lambda_function_name)"
  LOG_GROUP="$(tf_out lambda_log_group)"
  export INCIDENT_BUCKET TEST_BUCKET TEST_USER TEST_POLICY_ARN TRAIL_NAME LAMBDA_NAME LOG_GROUP
}

# Save a command's stdout+stderr to raw evidence and a redacted copy.
# save_evidence <name> -- <command...>
save_evidence() {
  local name="$1"; shift; [ "$1" = "--" ] && shift
  mkdir -p "$EVIDENCE_RAW" "$EVIDENCE_DIR"
  local raw="$EVIDENCE_RAW/$name" out="$EVIDENCE_DIR/$name"
  {
    echo "# \$ $*"
    echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    "$@" 2>&1 || echo "# exit code: $?"
  } > "$raw"
  "$REDACT" < "$raw" > "$out"
  log "evidence saved: docs/evidence/$name"
}

# Poll the incident bucket for a report matching event_name created after $since
# (epoch seconds). Prints the S3 key on success. Times out after $timeout seconds.
wait_for_incident() {
  local event_name="$1" since="$2" timeout="${3:-900}" interval="${4:-20}"
  local deadline=$(( $(date +%s) + timeout ))
  local today prefix
  while [ "$(date +%s)" -lt "$deadline" ]; do
    for day_offset in 0 1; do
      today="$(date -u -v-"${day_offset}"d +%Y/%m/%d 2>/dev/null || date -u -d "-${day_offset} day" +%Y/%m/%d)"
      prefix="incidents/$today/"
      local keys
      keys="$(aws s3api list-objects-v2 --bucket "$INCIDENT_BUCKET" --prefix "$prefix" \
                --query "Contents[?LastModified>='$(date -u -r "$since" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d @"$since" +%Y-%m-%dT%H:%M:%SZ)'].Key" \
                --output text 2>/dev/null || true)"
      for key in $keys; do
        [ "$key" = "None" ] && continue
        local body
        body="$(aws s3 cp "s3://$INCIDENT_BUCKET/$key" - 2>/dev/null || true)"
        if printf '%s' "$body" | grep -q "\"event_name\": \"$event_name\""; then
          echo "$key"; return 0
        fi
      done
    done
    log "waiting for $event_name incident ... ($(( deadline - $(date +%s) ))s left)"
    sleep "$interval"
  done
  return 1
}

# Confirm that NO incident for event_name appeared after $since within $window seconds.
assert_no_incident() {
  local event_name="$1" since="$2" window="${3:-300}"
  log "negative check: waiting ${window}s to confirm no $event_name incident appears"
  if wait_for_incident "$event_name" "$since" "$window" 30; then
    return 1
  fi
  return 0
}

# CloudTrail lookup (can lag up to ~15 min). Prints JSON of matching events.
lookup_events() {
  local event_name="$1" since="$2" timeout="${3:-900}"
  local deadline=$(( $(date +%s) + timeout )) start_iso
  start_iso="$(date -u -r "$since" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d @"$since" +%Y-%m-%dT%H:%M:%SZ)"
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local out
    out="$(aws cloudtrail lookup-events --lookup-attributes "AttributeKey=EventName,AttributeValue=$event_name" \
            --start-time "$start_iso" --max-results 5 --output json 2>/dev/null || true)"
    if printf '%s' "$out" | grep -q '"EventId"'; then
      printf '%s\n' "$out"; return 0
    fi
    log "waiting for CloudTrail lookup-events to show $event_name ... ($(( deadline - $(date +%s) ))s left)"
    sleep 30
  done
  return 1
}

# Lambda log lines mentioning the given string, since $since.
lambda_logs() {
  local needle="$1" since="$2"
  aws logs filter-log-events --log-group-name "$LOG_GROUP" \
    --start-time "$(( since * 1000 ))" --filter-pattern "\"$needle\"" \
    --query 'events[].message' --output text
}
