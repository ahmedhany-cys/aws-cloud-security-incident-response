#!/usr/bin/env bash
# Runs the controlled test scenarios T1-T6 against the dedicated TEST resources
# only, restores state after each, and saves redacted evidence under
# docs/evidence/. Usage:
#   scripts/run_test_scenarios.sh            # all scenarios
#   scripts/run_test_scenarios.sh T1 T3      # a subset
# Env: AWS_PROFILE (default sec-ir), INCIDENT_TIMEOUT (s, default 900),
#      NEGATIVE_WINDOW (s, default 300)
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
load_outputs

INCIDENT_TIMEOUT="${INCIDENT_TIMEOUT:-900}"
NEGATIVE_WINDOW="${NEGATIVE_WINDOW:-300}"
RESULTS_FILE="$EVIDENCE_DIR/results.tsv"
mkdir -p "$EVIDENCE_RAW" "$EVIDENCE_DIR"

# Safety: every target must carry the project tag / prefix.
[[ "$TEST_BUCKET" == aws-sec-ir-test-bucket-* ]] || die "unexpected test bucket name: $TEST_BUCKET"
[[ "$TEST_USER"   == aws-sec-ir-test-user ]]     || die "unexpected test user: $TEST_USER"
[[ "$TEST_POLICY_ARN" == *":policy/aws-sec-ir/aws-sec-ir-test-policy" ]] || die "unexpected test policy: $TEST_POLICY_ARN"

record() { printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$RESULTS_FILE"; }

# collect <id> <event_name> <since>  -> pass/fail for a positive scenario
collect_positive() {
  local id="$1" event_name="$2" since="$3" key
  if key="$(wait_for_incident "$event_name" "$since" "$INCIDENT_TIMEOUT")"; then
    log "$id: incident found at s3://$INCIDENT_BUCKET/$key"
    save_evidence "$id-incident.json" -- aws s3 cp "s3://$INCIDENT_BUCKET/$key" -
    local event_id; event_id="$(basename "$key" .json)"
    save_evidence "$id-lambda-log.txt" -- lambda_logs "$event_id" "$since"
    if lookup_events "$event_name" "$since" "$INCIDENT_TIMEOUT" > "$EVIDENCE_RAW/$id-cloudtrail-lookup.json"; then
      "$REDACT" < "$EVIDENCE_RAW/$id-cloudtrail-lookup.json" > "$EVIDENCE_DIR/$id-cloudtrail-lookup.json"
    else
      echo "# lookup-events did not return $event_name within timeout" > "$EVIDENCE_DIR/$id-cloudtrail-lookup.json"
    fi
    record "$id" "$event_name" "PASS" "$key"
  else
    log "$id: FAIL - no $event_name incident within ${INCIDENT_TIMEOUT}s"
    record "$id" "$event_name" "FAIL" "no incident within ${INCIDENT_TIMEOUT}s"
    return 1
  fi
}

t1() { # IAM policy attach -> HIGH AttachUserPolicy
  local since; since="$(date +%s)"
  save_evidence "T1-command.txt" -- aws iam attach-user-policy --user-name "$TEST_USER" --policy-arn "$TEST_POLICY_ARN"
  sleep 2
  save_evidence "T1-restore.txt" -- aws iam detach-user-policy --user-name "$TEST_USER" --policy-arn "$TEST_POLICY_ARN"
  save_evidence "T1-verify-restored.txt" -- aws iam list-attached-user-policies --user-name "$TEST_USER"
  collect_positive T1 AttachUserPolicy "$since"
}

t2() { # Inline policy put -> HIGH PutUserPolicy
  local since; since="$(date +%s)"
  local doc='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}'
  save_evidence "T2-command.txt" -- aws iam put-user-policy --user-name "$TEST_USER" --policy-name aws-sec-ir-t2-inline --policy-document "$doc"
  sleep 2
  save_evidence "T2-restore.txt" -- aws iam delete-user-policy --user-name "$TEST_USER" --policy-name aws-sec-ir-t2-inline
  save_evidence "T2-verify-restored.txt" -- aws iam list-user-policies --user-name "$TEST_USER"
  collect_positive T2 PutUserPolicy "$since"
}

t3() { # Disable logging -> CRITICAL StopLogging; restart immediately
  local since; since="$(date +%s)"
  save_evidence "T3-command.txt" -- aws cloudtrail stop-logging --name "$TRAIL_NAME"
  save_evidence "T3-restore.txt" -- aws cloudtrail start-logging --name "$TRAIL_NAME"
  save_evidence "T3-verify-restored.txt" -- aws cloudtrail get-trail-status --name "$TRAIL_NAME"
  grep -q '"IsLogging": true' "$EVIDENCE_RAW/T3-verify-restored.txt" || die "T3: trail is NOT logging after restore - fix this before anything else"
  collect_positive T3 StopLogging "$since"
}

t4() { # S3 bucket policy change on the TEST bucket -> HIGH PutBucketPolicy
  local since; since="$(date +%s)"
  local original="$EVIDENCE_RAW/T4-original-policy.json"
  aws s3api get-bucket-policy --bucket "$TEST_BUCKET" --query Policy --output text > "$original"
  local harmless
  harmless="$(printf '{"Version":"2012-10-17","Statement":[{"Sid":"AwsSecIrTestMarker","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::%s","arn:aws:s3:::%s/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}' "$TEST_BUCKET" "$TEST_BUCKET")"
  save_evidence "T4-command.txt" -- aws s3api put-bucket-policy --bucket "$TEST_BUCKET" --policy "$harmless"
  sleep 2
  save_evidence "T4-delete.txt" -- aws s3api delete-bucket-policy --bucket "$TEST_BUCKET"
  save_evidence "T4-restore.txt" -- aws s3api put-bucket-policy --bucket "$TEST_BUCKET" --policy "file://$original"
  save_evidence "T4-verify-restored.txt" -- aws s3api get-bucket-policy --bucket "$TEST_BUCKET"
  collect_positive T4 PutBucketPolicy "$since"
}

t5() { # Public access block removal on the TEST bucket -> HIGH DeleteBucketPublicAccessBlock
  # (API: delete-public-access-block; CloudTrail event name: DeleteBucketPublicAccessBlock)
  local since; since="$(date +%s)"
  save_evidence "T5-command.txt" -- aws s3api delete-public-access-block --bucket "$TEST_BUCKET"
  sleep 2
  save_evidence "T5-restore.txt" -- aws s3api put-public-access-block --bucket "$TEST_BUCKET" \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  save_evidence "T5-verify-restored.txt" -- aws s3api get-public-access-block --bucket "$TEST_BUCKET"
  grep -c true "$EVIDENCE_RAW/T5-verify-restored.txt" | grep -q 4 || die "T5: public access block not fully restored"
  collect_positive T5 DeleteBucketPublicAccessBlock "$since"
}

t6() { # Negative test: benign calls must NOT create incidents
  local since; since="$(date +%s)"
  save_evidence "T6-command.txt" -- aws iam list-users --max-items 5
  save_evidence "T6-command-2.txt" -- aws s3 ls
  if assert_no_incident ListUsers "$since" "$NEGATIVE_WINDOW" && assert_no_incident ListBuckets "$since" "$NEGATIVE_WINDOW"; then
    save_evidence "T6-incident-listing.txt" -- aws s3api list-objects-v2 --bucket "$INCIDENT_BUCKET" --prefix "incidents/$(date -u +%Y/%m/%d)/" --query 'Contents[].{Key:Key,LastModified:LastModified}' --output table
    save_evidence "T6-lambda-log.txt" -- lambda_logs "ListUsers" "$since"
    record T6 "ListUsers/ListBuckets" PASS "no incident within ${NEGATIVE_WINDOW}s"
  else
    record T6 "ListUsers/ListBuckets" FAIL "an incident WAS created for a benign call"
    return 1
  fi
}

scenarios=("$@"); [ ${#scenarios[@]} -eq 0 ] && scenarios=(T1 T2 T3 T4 T5 T6)
printf 'scenario\tevent\tresult\tdetail\n' > "$RESULTS_FILE"
status=0
for s in "${scenarios[@]}"; do
  log "===== $s ====="
  case "$s" in
    T1) t1 || status=1 ;; T2) t2 || status=1 ;; T3) t3 || status=1 ;;
    T4) t4 || status=1 ;; T5) t5 || status=1 ;; T6) t6 || status=1 ;;
    *) die "unknown scenario $s" ;;
  esac
done
log "===== results ====="
cat "$RESULTS_FILE" >&2
exit $status
