"""Core logic shared by the Lambda handler and the CLI.

Owner lookup uses ``iam:GetAccessKeyLastUsed``, which returns the owning
user name in a single API call. The previous implementation paginated over
every IAM user and listed each user's keys, which is O(users) API calls and
will be throttled or time out in a large account.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Long-term IAM user access key IDs are "AKIA" followed by 16 uppercase
# alphanumerics. Temporary STS credentials start with "ASIA" and cannot be
# deactivated through UpdateAccessKey, so they are intentionally rejected.
ACCESS_KEY_ID_PATTERN = re.compile(r"AKIA[0-9A-Z]{16}")


class KeyNotFoundError(LookupError):
    """Raised when no IAM user in the account owns the given access key."""


@dataclass(frozen=True)
class RemediationResult:
    access_key_id: str
    user_name: str
    status: str


def is_valid_access_key_id(value: str) -> bool:
    """Return True if ``value`` is exactly one well-formed long-term key ID."""
    return bool(ACCESS_KEY_ID_PATTERN.fullmatch(value))


def find_key_owner(iam_client, access_key_id: str) -> str:
    """Return the IAM user name that owns ``access_key_id``.

    Raises:
        KeyNotFoundError: the key does not exist in this account.
        ClientError: any other IAM API failure.
    """
    try:
        response = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            raise KeyNotFoundError(access_key_id) from exc
        raise

    user_name = response.get("UserName")
    if not user_name:
        raise KeyNotFoundError(access_key_id)
    return user_name


def deactivate_access_key(iam_client, access_key_id: str) -> RemediationResult:
    """Locate the owner of ``access_key_id`` and set the key to Inactive.

    Raises:
        ValueError: the key ID is not well-formed.
        KeyNotFoundError: no user owns the key.
        ClientError: IAM rejected the lookup or the update.
    """
    if not is_valid_access_key_id(access_key_id):
        raise ValueError(f"Invalid AWS access key ID format: {access_key_id!r}")

    logger.info("Looking up owner for access key %s", access_key_id)
    user_name = find_key_owner(iam_client, access_key_id)
    logger.info("Access key %s is owned by user %s", access_key_id, user_name)

    iam_client.update_access_key(
        UserName=user_name,
        AccessKeyId=access_key_id,
        Status="Inactive",
    )
    logger.info("Access key %s deactivated", access_key_id)
    return RemediationResult(
        access_key_id=access_key_id,
        user_name=user_name,
        status="Inactive",
    )
