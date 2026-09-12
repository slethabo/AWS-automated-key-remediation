output "lambda_function_name" {
  description = "Name of the remediation Lambda."
  value       = aws_lambda_function.remediation.function_name
}

output "lambda_function_arn" {
  description = "ARN of the remediation Lambda."
  value       = aws_lambda_function.remediation.arn
}

output "lambda_role_arn" {
  description = "Execution role ARN (useful when auditing what the function can do)."
  value       = aws_iam_role.lambda.arn
}

output "log_group_name" {
  description = "CloudWatch log group. Tail with: aws logs tail <name> --follow"
  value       = aws_cloudwatch_log_group.lambda.name
}

output "dead_letter_queue_url" {
  description = "SQS queue receiving failed invocations and undeliverable events."
  value       = aws_sqs_queue.dlq.url
}

output "guardduty_rule_name" {
  description = "EventBridge rule for GuardDuty findings (null if disabled)."
  value       = var.enable_guardduty_trigger ? aws_cloudwatch_event_rule.guardduty[0].name : null
}

output "health_rule_name" {
  description = "EventBridge rule for AWS Health exposed-credential events (null if disabled)."
  value       = var.enable_health_trigger ? aws_cloudwatch_event_rule.health[0].name : null
}
