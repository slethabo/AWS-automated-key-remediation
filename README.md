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
tests/                      pytest + moto (no AWS account needed)
.github/workflows/ci.yml    Lint, test on Python 3.12/3.13, build Lambda zip
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

Deploy by zipping the contents of `src/` (CI produces this artifact on every
green run of `main`). `boto3` is provided by the Lambda runtime.

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

- Trigger from `AWS_RISK_CREDENTIALS_EXPOSED` Health events and GuardDuty
  findings via EventBridge
- Pull the key's recent CloudTrail activity into a forensic report
- Notify via SNS and record every action for audit
- Terraform for the Lambda, role, and EventBridge rules
