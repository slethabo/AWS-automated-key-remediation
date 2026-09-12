data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    # Confused-deputy guard: only Lambda functions in this account may assume.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.project_name}-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# The function needs exactly two IAM actions. UpdateAccessKey is scoped to
# IAM users only (not roles, not the root account). GetAccessKeyLastUsed
# does not support resource-level permissions, so it must be "*".
data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "LookupKeyOwner"
    actions   = ["iam:GetAccessKeyLastUsed"]
    resources = ["*"]
  }

  statement {
    sid       = "DeactivateUserKeys"
    actions   = ["iam:UpdateAccessKey"]
    resources = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:user/*"]
  }

  statement {
    sid = "WriteLogs"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid       = "DeadLetter"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.dlq.arn]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${var.project_name}-lambda"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}
