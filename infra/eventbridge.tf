locals {
  # EventBridge "anything-but" rejects an empty list, so only add the
  # exemption clause when there is something to exempt.
  access_key_details_filter = merge(
    { userType = ["IAMUser"] },
    length(var.exempt_user_names) > 0
    ? { userName = [{ anything-but = var.exempt_user_names }] }
    : {}
  )

  guardduty_pattern = {
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      type     = [for t in var.guardduty_finding_types : { prefix = t }]
      severity = [{ numeric = [">=", var.guardduty_min_severity] }]
      resource = {
        resourceType     = ["AccessKey"]
        accessKeyDetails = local.access_key_details_filter
      }
    }
  }

  health_pattern = {
    source        = ["aws.health"]
    "detail-type" = ["AWS Health Event"]
    detail = {
      service = ["RISK"]
      eventTypeCode = [
        "AWS_RISK_CREDENTIALS_EXPOSED",
        "AWS_RISK_CREDENTIALS_COMPROMISED",
      ]
    }
  }
}

# ---------------------------------------------------------------------------
# GuardDuty: IAM user access key findings
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "guardduty" {
  count = var.enable_guardduty_trigger ? 1 : 0

  name          = "${var.project_name}-guardduty"
  description   = "Route high-severity GuardDuty IAM access key findings to the remediation Lambda"
  event_pattern = jsonencode(local.guardduty_pattern)
}

resource "aws_cloudwatch_event_target" "guardduty" {
  count = var.enable_guardduty_trigger ? 1 : 0

  rule = aws_cloudwatch_event_rule.guardduty[0].name
  arn  = aws_lambda_function.remediation.arn

  # Reshape the finding into the handler's expected payload. Extra fields are
  # carried along so they appear in the Lambda logs for audit.
  input_transformer {
    input_paths = {
      access_key_id = "$.detail.resource.accessKeyDetails.accessKeyId"
      user_name     = "$.detail.resource.accessKeyDetails.userName"
      finding_id    = "$.detail.id"
      finding_type  = "$.detail.type"
      severity      = "$.detail.severity"
    }
    input_template = <<-EOT
      {
        "access_key_id": <access_key_id>,
        "source": "guardduty",
        "finding_id": <finding_id>,
        "finding_type": <finding_type>,
        "severity": <severity>,
        "user_name": <user_name>
      }
    EOT
  }

  retry_policy {
    maximum_retry_attempts       = 2
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_lambda_permission" "guardduty" {
  count = var.enable_guardduty_trigger ? 1 : 0

  statement_id  = "AllowEventBridgeGuardDuty"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty[0].arn
}

# ---------------------------------------------------------------------------
# AWS Health: credentials AWS itself found exposed (e.g. public GitHub)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "health" {
  count = var.enable_health_trigger ? 1 : 0

  name          = "${var.project_name}-health-exposed-credentials"
  description   = "Route AWS Health exposed-credential events to the remediation Lambda"
  event_pattern = jsonencode(local.health_pattern)
}

resource "aws_cloudwatch_event_target" "health" {
  count = var.enable_health_trigger ? 1 : 0

  rule = aws_cloudwatch_event_rule.health[0].name
  arn  = aws_lambda_function.remediation.arn

  # Known limitation: only the first affected entity is remediated. A Health
  # event listing several exposed keys needs native event parsing in the
  # handler (tracked in the README roadmap).
  input_transformer {
    input_paths = {
      access_key_id = "$.detail.affectedEntities[0].entityValue"
      event_arn     = "$.detail.eventArn"
      event_type    = "$.detail.eventTypeCode"
    }
    input_template = <<-EOT
      {
        "access_key_id": <access_key_id>,
        "source": "health",
        "event_arn": <event_arn>,
        "event_type": <event_type>
      }
    EOT
  }

  retry_policy {
    maximum_retry_attempts       = 2
    maximum_event_age_in_seconds = 3600
  }

  dead_letter_config {
    arn = aws_sqs_queue.dlq.arn
  }
}

resource "aws_lambda_permission" "health" {
  count = var.enable_health_trigger ? 1 : 0

  statement_id  = "AllowEventBridgeHealth"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.health[0].arn
}

# EventBridge needs permission to write undeliverable events to the DLQ.
data "aws_iam_policy_document" "dlq" {
  statement {
    sid       = "AllowEventBridgeDeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = compact([
        var.enable_guardduty_trigger ? aws_cloudwatch_event_rule.guardduty[0].arn : "",
        var.enable_health_trigger ? aws_cloudwatch_event_rule.health[0].arn : "",
      ])
    }
  }
}

resource "aws_sqs_queue_policy" "dlq" {
  count = var.enable_guardduty_trigger || var.enable_health_trigger ? 1 : 0

  queue_url = aws_sqs_queue.dlq.id
  policy    = data.aws_iam_policy_document.dlq.json
}

# ---------------------------------------------------------------------------
# Optional: turn GuardDuty on. Skip if it is already enabled in this account.
# ---------------------------------------------------------------------------

resource "aws_guardduty_detector" "this" {
  count = var.enable_guardduty_detector ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}
