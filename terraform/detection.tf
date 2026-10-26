# One EventBridge rule per detection category on the default bus. Matching
# "AWS API Call via CloudTrail" events is free; only the Lambda invocation is
# metered (and well inside the free tier).
resource "aws_cloudwatch_event_rule" "detection" {
  for_each = local.detection_rules

  name        = "${var.name_prefix}-${each.key}"
  description = each.value.description

  event_pattern = jsonencode({
    source      = [each.value.source]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = [each.value.event_source]
      eventName   = each.value.event_names
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  for_each = aws_cloudwatch_event_rule.detection

  rule      = each.value.name
  target_id = "incident-processor"
  arn       = aws_lambda_function.incident_processor.arn
}

# Lambda resource policy: only EventBridge, and only these exact rules, may
# invoke the function (one permission statement per rule ARN).
resource "aws_lambda_permission" "allow_eventbridge" {
  for_each = aws_cloudwatch_event_rule.detection

  statement_id  = "AllowInvokeFrom-${each.key}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.incident_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value.arn
}
