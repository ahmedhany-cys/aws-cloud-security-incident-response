#!/usr/bin/env bash
# Collects general (non-scenario) evidence about the deployed stack and saves
# redacted copies under docs/evidence/. Safe: read-only AWS calls.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
load_outputs

save_evidence "00-caller-identity.json"  -- aws sts get-caller-identity
save_evidence "01-terraform-outputs.txt" -- terraform -chdir="$TF_DIR" output
save_evidence "02-trail-status.json"     -- aws cloudtrail get-trail-status --name "$TRAIL_NAME"
save_evidence "03-trail-config.json"     -- aws cloudtrail get-trail --name "$TRAIL_NAME"
save_evidence "04-trail-event-selectors.json" -- aws cloudtrail get-event-selectors --trail-name "$TRAIL_NAME"
save_evidence "05-eventbridge-rules.json" -- aws events list-rules --name-prefix aws-sec-ir-
for rule in $(aws events list-rules --name-prefix aws-sec-ir- --query 'Rules[].Name' --output text); do
  save_evidence "06-rule-$rule.json" -- aws events describe-rule --name "$rule"
  save_evidence "06-rule-$rule-targets.json" -- aws events list-targets-by-rule --rule "$rule"
done
save_evidence "07-lambda-config.json"    -- aws lambda get-function-configuration --function-name "$LAMBDA_NAME"
save_evidence "08-lambda-policy.json"    -- aws lambda get-policy --function-name "$LAMBDA_NAME"
save_evidence "09-log-group.json"        -- aws logs describe-log-groups --log-group-name-prefix "$LOG_GROUP"
for b in "$(tf_out audit_bucket)" "$INCIDENT_BUCKET" "$TEST_BUCKET"; do
  save_evidence "10-bucket-$b-public-access-block.json" -- aws s3api get-public-access-block --bucket "$b"
  save_evidence "10-bucket-$b-encryption.json" -- aws s3api get-bucket-encryption --bucket "$b"
  save_evidence "10-bucket-$b-versioning.json" -- aws s3api get-bucket-versioning --bucket "$b"
  save_evidence "10-bucket-$b-lifecycle.json" -- aws s3api get-bucket-lifecycle-configuration --bucket "$b"
done
save_evidence "11-incident-objects.txt"  -- aws s3 ls "s3://$INCIDENT_BUCKET/incidents/" --recursive
if [ "$(tf_out trail_health_check_function_name 2>/dev/null)" != "null" ] && tf_out trail_health_check_function_name >/dev/null 2>&1; then
  save_evidence "13-health-check-lambda-config.json" -- aws lambda get-function-configuration --function-name "$(tf_out trail_health_check_function_name)"
  save_evidence "14-health-check-schedule.json" -- aws scheduler get-schedule --group-name aws-sec-ir --name aws-sec-ir-trail-health-check
fi
save_evidence "12-project-tagged-resources.json" -- aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=aws-sec-ir --query 'ResourceTagMappingList[].ResourceARN'
log "done"
