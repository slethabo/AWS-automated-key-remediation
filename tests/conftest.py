import os

import boto3
import pytest
from moto import mock_aws

# moto refuses to run without credentials and a region in the environment.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def iam():
    with mock_aws():
        yield boto3.client("iam")


@pytest.fixture
def user_with_key(iam):
    """Create an IAM user with one active access key; return (user_name, key_id)."""
    iam.create_user(UserName="alice")
    key = iam.create_access_key(UserName="alice")["AccessKey"]
    return "alice", key["AccessKeyId"]


def key_status(iam, user_name: str, access_key_id: str) -> str:
    keys = iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    return next(k["Status"] for k in keys if k["AccessKeyId"] == access_key_id)
