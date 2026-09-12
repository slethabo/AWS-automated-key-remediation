# AWS Automated Key Remediation

[![CI](https://github.com/slethabo/AWS-automated-key-remediation/actions/workflows/ci.yml/badge.svg)](https://github.com/slethabo/AWS-automated-key-remediation/actions/workflows/ci.yml)

A serverless incident-response tool that deactivates a compromised AWS IAM
access key. Given an access key ID, it resolves the owning IAM user with a
single `iam:GetAccessKeyLastUsed` call and sets the key to `Inactive`.

## Layout

```
src/
  lambda_function.py        Lambda handler (lambda_function.lambda_handler)
  key_remediation/
    core.py                 Validation, owner lookup, deactivation
    cli.py                  Manual CLI: python -m key_remediation.cli AKIA...
infra/                      Terraform: Lambda, least-privilege role, EventBridge
                            rules for GuardDuty + AWS Health, SQS dead-letter queue
tests/                      pytest + moto (no AWS account needed)
.github/workflows/ci.yml    Lint, test on Python 3.12/3.13, terraform validate,
                            build Lambda zip
```

## Architecture

```mermaid
flowchart LR
    GD[GuardDuty finding<br/>IAMUser access key<br/>severity >= 7] --> R1[EventBridge rule<br/>type allowlist<br/>user exemptions]
    AH[AWS Health<br/>CREDENTIALS_EXPOSED] --> R2[EventBridge rule]
    R1 -- "{access_key_id}" --> L[Lambda<br/>key_remediation]
    R2 -- "{access_key_id}" --> L
    L -->|GetAccessKeyLastUsed| IAM[(IAM)]
    L -->|UpdateAccessKey Inactive| IAM
    L -. failures .-> DLQ[SQS dead-letter queue]
    R1 -. undeliverable .-> DLQ
    R2 -. undeliverable .-> DLQ
```

## How it works

1. Validate the input is a well-formed long-term key ID (`AKIA` + 16 chars).
   Temporary STS credentials (`ASIA...`) are rejected because they cannot be
   deactivated with `UpdateAccessKey`.
2. Call `GetAccessKeyLastUsed` to get the owning user name. This is one API
   call regardless of account size. The original version paginated over every
   IAM user and listed each user's keys, which is O(users) calls and would be
   throttled or time out in a large account.
3. Call `UpdateAccessKey` with `Status=Inactive`.

The key is deactivated, not deleted, so it can be re-enabled if the alert was
a false positive and its CloudTrail history is preserved for investigation.

## Lambda

Handler: `lambda_function.lambda_handler`
Runtime: Python 3.12 or 3.13

Event payload (either key name is accepted):

```json
{"access_key_id": "AKIAIOSFODNN7EXAMPLE"}
```

Responses:

| statusCode | Meaning                                  |
|------------|------------------------------------------|
| 200        | Key deactivated; body includes `user`    |
| 400        | Missing or malformed access key ID       |
| 404        | No IAM user in this account owns the key |
| 500        | IAM API call failed                      |

Minimum IAM policy for the execution role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:GetAccessKeyLastUsed", "iam:UpdateAccessKey"],
      "Resource": "*"
    }
  ]
}
```

## Deploy

```
cd infra
cp terraform.tfvars.example terraform.tfvars   # set exempt_user_names etc.
terraform init && terraform apply
```

This creates the function, its role, log group, dead-letter queue, and the
EventBridge rules that wire GuardDuty and AWS Health findings into it. See
[`infra/README.md`](infra/README.md) for every resource, the built-in
guardrails, and how to fire a sample GuardDuty finding to test the pipeline.

CI also produces a plain zip of `src/` as an artifact on every green run of
`main` if you prefer to deploy by hand. `boto3` is provided by the Lambda
runtime.

## CLI

```
pip install -r requirements.txt
python -m key_remediation.cli AKIAIOSFODNN7EXAMPLE [--profile NAME] [-v]
```

Exit codes: `0` deactivated, `1` not found or IAM error, `2` invalid format.

## Development

```
pip install -r requirements-dev.txt
pytest
ruff check . && ruff format --check .
```

Tests run against [moto](https://github.com/getmoto/moto), so no AWS
credentials or account are required.

## Security considerations

Anyone who can invoke this function can deactivate any access key in the
account. Restrict `lambda:InvokeFunction` on it to the detection pipeline
(for example an EventBridge rule) and treat that permission as sensitive.

## Roadmap

- Parse GuardDuty and Health events natively in the handler so Health
  events listing several exposed keys remediate all of them
- Pull the key's recent CloudTrail activity into a forensic report in S3
- Notify via SNS and record every action in DynamoDB for audit
- Attack lab: Terraform for a victim user plus Stratus Red Team runbook to
  generate real findings and measure time to remediation
