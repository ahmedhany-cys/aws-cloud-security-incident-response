# Root module. The stack is small enough to live in one root module; the files
# are split by concern instead of by Terraform module:
#   main.tf            data sources + shared locals (this file)
#   s3.tf              audit-logs, incident-reports and test buckets
#   cloudtrail.tf      the single management-events trail
#   detection.tf       EventBridge rules -> Lambda targets + invoke permissions
#   responder.tf       Lambda function, execution role, log group
#   notifications.tf   optional SNS topic (enable_email_alerts)
#   test_resources.tf  throwaway IAM user / policy / bucket used by T1-T5
#   health_check.tf    scheduled GetTrailStatus check (closes the T3 blind spot)

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.name

  audit_bucket_name    = "${var.name_prefix}-audit-logs-${var.bucket_suffix}"
  incident_bucket_name = "${var.name_prefix}-incident-reports-${var.bucket_suffix}"
  test_bucket_name     = "${var.name_prefix}-test-bucket-${var.bucket_suffix}"

  trail_name = "${var.name_prefix}-trail"
  # The trail ARN is built by hand so the bucket policy can reference it before
  # the trail exists (the trail needs the bucket policy to be in place first).
  trail_arn = "arn:${local.partition}:cloudtrail:${local.region}:${local.account_id}:trail/${local.trail_name}"

  lambda_function_name = "${var.name_prefix}-incident-processor"
  lambda_log_group     = "/aws/lambda/${local.lambda_function_name}"

  # One EventBridge rule per detection category. Names are CloudTrail *event*
  # names, which are not always the API operation names: S3 logs the bucket-level
  # PutPublicAccessBlock API as PutBucketPublicAccessBlock and the account-level
  # one as PutAccountPublicAccessBlock (S3 user guide, "Amazon S3 CloudTrail
  # events"). Verified 2026-10-26 against that page and against live
  # lookup-events output.
  detection_rules = {
    iam-policy-change = {
      description  = "IAM policy attached, created or inlined (privilege escalation path)"
      source       = "aws.iam"
      event_source = "iam.amazonaws.com"
      event_names = [
        "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy",
        "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
        "CreatePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
      ]
    }
    logging-tamper = {
      description  = "CloudTrail logging stopped, deleted or reconfigured (defense evasion)"
      source       = "aws.cloudtrail"
      event_source = "cloudtrail.amazonaws.com"
      event_names  = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
    }
    s3-permission-change = {
      description  = "S3 bucket policy, ACL or public access block changed (data exposure path)"
      source       = "aws.s3"
      event_source = "s3.amazonaws.com"
      event_names = [
        "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl",
        "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
        "PutAccountPublicAccessBlock", "DeleteAccountPublicAccessBlock",
      ]
    }
  }
}
