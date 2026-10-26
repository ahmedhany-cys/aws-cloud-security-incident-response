# Optional email alerts. Off by default (enable_email_alerts = false), so no
# SNS resources exist unless you opt in. One topic, one email subscription.
resource "aws_sns_topic" "alerts" {
  count = var.enable_email_alerts ? 1 : 0
  name  = "${var.name_prefix}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.enable_email_alerts ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.alert_email
}
