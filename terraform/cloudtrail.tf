# Exactly one trail: management events only (read + write), single region,
# global service events on (so IAM calls are recorded), log file validation on
# (free). No data events, no Insights, no CloudWatch Logs delivery, no org
# trail. See docs/cost-notes.md.
resource "aws_cloudtrail" "main" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.this["audit"].id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
    # no data_resource blocks on purpose (data events cost money)
  }

  depends_on = [aws_s3_bucket_policy.audit]
}
