output "region" {
  value = local.region
}

output "audit_bucket" {
  description = "CloudTrail audit-logs bucket"
  value       = aws_s3_bucket.this["audit"].bucket
}

output "incident_bucket" {
  description = "Incident-reports bucket"
  value       = aws_s3_bucket.this["incidents"].bucket
}

output "test_bucket" {
  description = "Throwaway bucket used by T4/T5"
  value       = aws_s3_bucket.this["test"].bucket
}

output "test_user_name" {
  value = aws_iam_user.test.name
}

output "test_policy_arn" {
  value = aws_iam_policy.test.arn
}

output "trail_name" {
  value = aws_cloudtrail.main.name
}

output "trail_arn" {
  value = aws_cloudtrail.main.arn
}

output "lambda_function_name" {
  value = aws_lambda_function.incident_processor.function_name
}

output "lambda_log_group" {
  value = aws_cloudwatch_log_group.lambda.name
}

output "detection_rule_names" {
  value = [for r in aws_cloudwatch_event_rule.detection : r.name]
}

output "sns_topic_arn" {
  value = var.enable_email_alerts ? aws_sns_topic.alerts[0].arn : null
}
