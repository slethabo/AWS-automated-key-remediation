# Package the contents of ../src. boto3 ships with the Lambda runtime, so only
# our own code is zipped. The hash of the zip drives redeploys on code change.
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = "${path.module}/../src"
  output_path = "${path.module}/.build/${var.project_name}.zip"
  excludes    = ["__pycache__", "**/__pycache__/**", "**/*.pyc"]
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.project_name}"
  retention_in_days = var.log_retention_days
}

# Failed async invocations (EventBridge invokes Lambda asynchronously) land
# here after Lambda's built-in retries so a missed remediation is never silent.
resource "aws_sqs_queue" "dlq" {
  name                      = "${var.project_name}-dlq"
  message_retention_seconds = 1209600 # 14 days, the maximum
  sqs_managed_sse_enabled   = true
}

resource "aws_lambda_function" "remediation" {
  function_name = var.project_name
  description   = "Deactivates compromised IAM access keys reported by GuardDuty / AWS Health"
  role          = aws_iam_role.lambda.arn

  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256

  handler       = "lambda_function.lambda_handler"
  runtime       = var.lambda_runtime
  architectures = ["arm64"]
  memory_size   = 128
  timeout       = var.lambda_timeout_seconds

  reserved_concurrent_executions = var.lambda_reserved_concurrency

  dead_letter_config {
    target_arn = aws_sqs_queue.dlq.arn
  }

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda,
  ]
}
