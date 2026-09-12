"""AWS Lambda entry point.

Handler: ``lambda_function.lambda_handler``

Expected event shape (either key is accepted):
    {"access_key_id": "AKIA..."}
    {"AccessKeyId": "AKIA..."}
"""

from __future__ import annotations

import json
import logging

import boto3
from botocore.exceptions import ClientError

from key_remediation.core import KeyNotFoundError, deactivate_access_key

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_iam_client = None


def _get_iam_client():
    """Lazily create and cache the IAM client across warm invocations."""
    global _iam_client
    if _iam_client is None:
        _iam_client = boto3.client("iam")
    return _iam_client


def _response(status_code: int, body: dict) -> dict:
    return {"statusCode": status_code, "body": json.dumps(body)}


def lambda_handler(event, context):
    raw_key = event.get("access_key_id") or event.get("AccessKeyId")
    if not raw_key:
        return _response(400, {"error": "No access_key_id provided in event."})

    access_key_id = str(raw_key).strip()

    try:
        result = deactivate_access_key(_get_iam_client(), access_key_id)
    except ValueError:
        return _response(400, {"error": "Invalid AWS access key ID format."})
    except KeyNotFoundError:
        logger.warning("Access key %s not found in this account", access_key_id)
        return _response(404, {"message": f"Key {access_key_id} not found."})
    except ClientError as exc:
        logger.error("IAM API call failed: %s", exc)
        return _response(500, {"error": str(exc)})

    return _response(
        200,
        {
            "message": f"Successfully deactivated key {result.access_key_id}",
            "user": result.user_name,
            "status": result.status,
        },
    )
