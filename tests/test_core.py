from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from key_remediation.core import (
    KeyNotFoundError,
    deactivate_access_key,
    find_key_owner,
    is_valid_access_key_id,
)
from tests.conftest import key_status

UNKNOWN_KEY = "AKIAZZZZZZZZZZZZZZZZ"


@pytest.mark.parametrize(
    "value",
    ["AKIAIOSFODNN7EXAMPLE", "AKIA0123456789ABCDEF"],
)
def test_valid_key_ids(value):
    assert is_valid_access_key_id(value)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "AKIA",
        "AKIAIOSFODNN7EXAMPL",  # 19 chars
        "AKIAIOSFODNN7EXAMPLE1",  # 21 chars
        "akiaiosfodnn7example",  # lowercase
        "ASIAIOSFODNN7EXAMPLE",  # temporary STS credential
        " AKIAIOSFODNN7EXAMPLE",  # leading whitespace
        "key=AKIAIOSFODNN7EXAMPLE",  # embedded in text
    ],
)
def test_invalid_key_ids(value):
    assert not is_valid_access_key_id(value)


def test_find_key_owner_returns_user(iam, user_with_key):
    user_name, key_id = user_with_key
    assert find_key_owner(iam, key_id) == user_name


def test_find_key_owner_unknown_key_raises(iam):
    with pytest.raises(KeyNotFoundError):
        find_key_owner(iam, UNKNOWN_KEY)


def test_find_key_owner_missing_username_raises():
    client = MagicMock()
    client.get_access_key_last_used.return_value = {"AccessKeyLastUsed": {}}
    with pytest.raises(KeyNotFoundError):
        find_key_owner(client, UNKNOWN_KEY)


def test_find_key_owner_reraises_other_client_errors():
    client = MagicMock()
    client.get_access_key_last_used.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GetAccessKeyLastUsed"
    )
    with pytest.raises(ClientError):
        find_key_owner(client, UNKNOWN_KEY)


def test_find_key_owner_uses_single_api_call():
    client = MagicMock()
    client.get_access_key_last_used.return_value = {"UserName": "alice"}
    find_key_owner(client, UNKNOWN_KEY)
    client.get_access_key_last_used.assert_called_once_with(AccessKeyId=UNKNOWN_KEY)
    client.list_users.assert_not_called()
    client.get_paginator.assert_not_called()


def test_deactivate_sets_key_inactive(iam, user_with_key):
    user_name, key_id = user_with_key
    assert key_status(iam, user_name, key_id) == "Active"

    result = deactivate_access_key(iam, key_id)

    assert result.user_name == user_name
    assert result.access_key_id == key_id
    assert result.status == "Inactive"
    assert key_status(iam, user_name, key_id) == "Inactive"


def test_deactivate_only_touches_target_key(iam, user_with_key):
    user_name, target = user_with_key
    other = iam.create_access_key(UserName=user_name)["AccessKey"]["AccessKeyId"]

    deactivate_access_key(iam, target)

    assert key_status(iam, user_name, target) == "Inactive"
    assert key_status(iam, user_name, other) == "Active"


def test_deactivate_is_idempotent(iam, user_with_key):
    user_name, key_id = user_with_key
    deactivate_access_key(iam, key_id)
    deactivate_access_key(iam, key_id)
    assert key_status(iam, user_name, key_id) == "Inactive"


def test_deactivate_invalid_format_raises_before_any_api_call():
    client = MagicMock()
    with pytest.raises(ValueError):
        deactivate_access_key(client, "not-a-key")
    client.get_access_key_last_used.assert_not_called()
    client.update_access_key.assert_not_called()


def test_deactivate_unknown_key_raises(iam):
    with pytest.raises(KeyNotFoundError):
        deactivate_access_key(iam, UNKNOWN_KEY)
