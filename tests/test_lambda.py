import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

import lambda_function
from tests.conftest import key_status


@pytest.fixture(autouse=True)
def inject_iam_client(iam, monkeypatch):
    """Point the handler's cached client at the moto-backed client."""
    monkeypatch.setattr(lambda_function, "_iam_client", iam)


def body(response):
    return json.loads(response["body"])


def test_missing_key_returns_400():
    response = lambda_function.lambda_handler({}, None)
    assert response["statusCode"] == 400
    assert "No access_key_id" in body(response)["error"]


@pytest.mark.parametrize(
    "payload", [{"access_key_id": "garbage"}, {"AccessKeyId": "ASIAIOSFODNN7EXAMPLE"}]
)
def test_invalid_format_returns_400(payload):
    response = lambda_function.lambda_handler(payload, None)
    assert response["statusCode"] == 400
    assert "Invalid" in body(response)["error"]


def test_unknown_key_returns_404():
    response = lambda_function.lambda_handler({"access_key_id": "AKIAZZZZZZZZZZZZZZZZ"}, None)
    assert response["statusCode"] == 404


def test_success_deactivates_key(iam, user_with_key):
    user_name, key_id = user_with_key

    response = lambda_function.lambda_handler({"access_key_id": key_id}, None)

    assert response["statusCode"] == 200
    assert body(response)["user"] == user_name
    assert body(response)["status"] == "Inactive"
    assert key_status(iam, user_name, key_id) == "Inactive"


def test_accepts_pascal_case_key_and_strips_whitespace(iam, user_with_key):
    user_name, key_id = user_with_key
    response = lambda_function.lambda_handler({"AccessKeyId": f"  {key_id}\n"}, None)
    assert response["statusCode"] == 200
    assert key_status(iam, user_name, key_id) == "Inactive"


def test_iam_failure_returns_500(monkeypatch):
    client = MagicMock()
    client.get_access_key_last_used.return_value = {"UserName": "alice"}
    client.update_access_key.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "UpdateAccessKey"
    )
    monkeypatch.setattr(lambda_function, "_iam_client", client)

    response = lambda_function.lambda_handler({"access_key_id": "AKIAIOSFODNN7EXAMPLE"}, None)

    assert response["statusCode"] == 500
    assert "AccessDenied" in body(response)["error"]
