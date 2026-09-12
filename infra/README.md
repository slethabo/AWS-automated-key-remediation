# Infrastructure

Terraform for the remediation Lambda and its detection triggers.

```
GuardDuty finding ──► EventBridge rule ──┐
  (IAMUser AccessKey,   (severity, type,  │  input transformer
   severity ≥ 7)         exemptions)      ├──────────────────► Lambda ──► iam:UpdateAccessKey
                                          │  {"access_key_id"}    │
AWS Health event  ──► EventBridge rule ──┘                       ▼
  (CREDENTIALS_EXPOSED)                                      SQS dead-letter queue
```

## What gets created

| Resource | Purpose |
|---|---|
| `aws_lambda_function.remediation` | The handler from `../src`, arm64, 128 MB, reserved concurrency 2 |
| `aws_iam_role.lambda` | Execution role: `iam:GetAccessKeyLastUsed`, `iam:UpdateAccessKey` on `user/*`, logs, DLQ |
| `aws_cloudwatch_log_group.lambda` | 90-day retention |
| `aws_sqs_queue.dlq` | Failed invocations and undeliverable events |
| `aws_cloudwatch_event_rule.guardduty` | Filters GuardDuty findings to IAM user access keys, allowed types, min severity, non-exempt users |
| `aws_cloudwatch_event_rule.health` | Filters `AWS_RISK_CREDENTIALS_EXPOSED` / `COMPROMISED` |
| `aws_guardduty_detector.this` | Optional, off by default |

## Deploy

```
cd infra
cp terraform.tfvars.example terraform.tfvars   # edit exemptions etc.
terraform init
terraform plan
terraform apply
```

Requires Terraform >= 1.5 and credentials with permission to create IAM
roles, Lambda functions, EventBridge rules, SQS queues, and log groups.

## Test the deployed function without waiting for a real finding

Send the handler a synthetic event directly:

```
aws lambda invoke \
  --function-name key-remediation \
  --cli-binary-format raw-in-base64-out \
  --payload '{"access_key_id":"AKIAIOSFODNN7EXAMPLE"}' \
  out.json && cat out.json
```

To exercise the EventBridge rule and input transformer as well, you need a
real GuardDuty finding. `aws events put-events` cannot spoof the
`aws.guardduty` source, so either generate a genuine finding (see the
project README on Stratus Red Team) or ask GuardDuty for a sample:

```
aws guardduty create-sample-findings \
  --detector-id $(aws guardduty list-detectors --query 'DetectorIds[0]' --output text) \
  --finding-types UnauthorizedAccess:IAMUser/MaliciousIPCaller
```

Sample findings reference a fake access key, so the Lambda will log a 404.
That still proves the rule, transformer, permission, and handler path work.

## Guardrails built in

- **Reserved concurrency of 2.** A burst of findings, or an attacker who
  learns how to trigger the pipeline, cannot mass-deactivate keys quickly.
- **Severity floor and finding-type allowlist** at the rule. Low-confidence
  findings never reach the function.
- **User exemptions** at the rule, so the Lambda is never invoked for
  break-glass identities.
- **`UpdateAccessKey` scoped to `user/*`.** The role cannot touch roles or
  the root account even if the handler were tricked.
- **Only EventBridge can invoke** the function, and only from these two
  rules, via `aws_lambda_permission` with `source_arn`.
- **Confused-deputy condition** on the role trust policy.

## Known limitations

- Health events listing several exposed keys only remediate the first.
  Native multi-entity parsing in the handler is on the roadmap.
- AWS Health events for IAM are delivered in `us-east-1` only. Deploying
  elsewhere still works for GuardDuty but the Health rule will never fire.
- Temporary credentials (`ASIA...`) from assumed roles are out of scope for
  `UpdateAccessKey` and are filtered out by `userType = IAMUser`.
