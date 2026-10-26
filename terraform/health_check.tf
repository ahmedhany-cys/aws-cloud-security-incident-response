# ---------------------------------------------------------------------------
# Scheduled trail health check.
#
# Why: test T3 showed that stopping the account's only trail can stop
# EventBridge from receiving that same StopLogging event (EventBridge only gets
# CloudTrail API events while a trail is logging). This check does not depend
# on CloudTrail delivery: EventBridge Scheduler invokes a Lambda every few
# minutes, the Lambda calls cloudtrail:GetTrailStatus, and writes a CRITICAL
# incident if the trail is not logging or no longer exists.
#
# Cost: ~8,640 schedule invocations and Lambda runs per month at 5-minute rate,
# far inside the Scheduler (14M/month) and Lambda (1M/month) free tiers.
# GetTrailStatus is a free control-plane call. See docs/cost-notes.md.
# ---------------------------------------------------------------------------

locals {
  health_function_name = "${var.name_prefix}-trail-health-check"
  health_log_group     = "/aws/lambda/${local.health_function_name}"
}

resource "aws_cloudwatch_log_group" "health" {
  count             = var.enable_trail_health_check ? 1 : 0
  name              = local.health_log_group
  retention_in_days = var.lambda_log_retention_days
}

resource "aws_iam_role" "health_lambda" {
  count              = var.enable_trail_health_check ? 1 : 0
  name               = "${var.name_prefix}-trail-health-check-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "health_lambda" {
  count = var.enable_trail_health_check ? 1 : 0

  # Read the status of this one trail only (GetTrailStatus supports the
  # trail resource type, so no "*" is needed).
  statement {
    sid       = "ReadProjectTrailStatus"
    effect    = "Allow"
    actions   = ["cloudtrail:GetTrailStatus"]
    resources = [local.trail_arn]
  }

  # Same write-only access to incidents/ as the incident processor.
  statement {
    sid       = "WriteIncidentReports"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.this["incidents"].arn}/incidents/*"]
  }

  # Own log group only; ":*" is required because stream names are generated
  # by the Lambda runtime.
  statement {
    sid       = "WriteOwnLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.health[0].arn}:*"]
  }

  dynamic "statement" {
    for_each = var.enable_email_alerts ? [1] : []
    content {
      sid       = "PublishAlerts"
      effect    = "Allow"
      actions   = ["sns:Publish"]
      resources = [aws_sns_topic.alerts[0].arn]
    }
  }
}

resource "aws_iam_role_policy" "health_lambda" {
  count  = var.enable_trail_health_check ? 1 : 0
  name   = "${var.name_prefix}-trail-health-check-policy"
  role   = aws_iam_role.health_lambda[0].id
  policy = data.aws_iam_policy_document.health_lambda[0].json
}

# Same deployment package as the incident processor, different entry point.
resource "aws_lambda_function" "trail_health_check" {
  count         = var.enable_trail_health_check ? 1 : 0
  function_name = local.health_function_name
  description   = "Scheduled check: CRITICAL incident if the project trail is not logging"
  role          = aws_iam_role.health_lambda[0].arn
  handler       = "incident_processor.health_check_handler"
  runtime       = "python3.12"
  architectures = ["arm64"]
  memory_size   = 128
  timeout       = 30

  filename         = data.archive_file.incident_processor.output_path
  source_code_hash = data.archive_file.incident_processor.output_base64sha256

  environment {
    variables = {
      INCIDENT_BUCKET = aws_s3_bucket.this["incidents"].bucket
      TRAIL_ARN       = local.trail_arn
      SNS_TOPIC_ARN   = var.enable_email_alerts ? aws_sns_topic.alerts[0].arn : ""
      LOG_LEVEL       = "INFO"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.health,
    aws_iam_role_policy.health_lambda,
  ]
}

# --- EventBridge Scheduler ---------------------------------------------------

# A dedicated group so the schedule can carry the Project tag (individual
# schedules are not taggable; schedule groups are).
resource "aws_scheduler_schedule_group" "project" {
  count = var.enable_trail_health_check ? 1 : 0
  name  = var.name_prefix
}

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    # Only schedules in this account may assume the role (confused-deputy guard).
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  count              = var.enable_trail_health_check ? 1 : 0
  name               = "${var.name_prefix}-scheduler-role"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

resource "aws_iam_role_policy" "scheduler" {
  count = var.enable_trail_health_check ? 1 : 0
  name  = "${var.name_prefix}-scheduler-invoke-health-check"
  role  = aws_iam_role.scheduler[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "InvokeHealthCheckOnly"
      Effect   = "Allow"
      Action   = "lambda:InvokeFunction"
      Resource = aws_lambda_function.trail_health_check[0].arn
    }]
  })
}

resource "aws_scheduler_schedule" "trail_health_check" {
  count       = var.enable_trail_health_check ? 1 : 0
  name        = "${var.name_prefix}-trail-health-check"
  group_name  = aws_scheduler_schedule_group.project[0].name
  description = "Invoke the trail health check Lambda"

  schedule_expression = var.trail_health_check_schedule
  state               = "ENABLED"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.trail_health_check[0].arn
    role_arn = aws_iam_role.scheduler[0].arn

    # The next run is only minutes away, so do not pile up retries.
    retry_policy {
      maximum_retry_attempts       = 2
      maximum_event_age_in_seconds = 300
    }
  }

  depends_on = [aws_iam_role_policy.scheduler]
}
