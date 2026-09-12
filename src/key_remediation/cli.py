"""Command-line entry point for manual remediation.

Usage:
    python -m key_remediation.cli AKIAIOSFODNN7EXAMPLE
"""

from __future__ import annotations

import argparse
import logging
import sys

import boto3
from botocore.exceptions import ClientError

from key_remediation.core import KeyNotFoundError, deactivate_access_key


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="key-remediation",
        description="Deactivate a compromised AWS IAM access key.",
    )
    parser.add_argument("access_key_id", help="Access key ID to deactivate, e.g. AKIA...")
    parser.add_argument(
        "--profile",
        help="AWS CLI profile to use (defaults to the standard credential chain).",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")
    return parser


def main(argv: list[str] | None = None, iam_client=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    if iam_client is None:
        session = boto3.Session(profile_name=args.profile)
        iam_client = session.client("iam")

    try:
        result = deactivate_access_key(iam_client, args.access_key_id.strip())
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyNotFoundError:
        print(f"error: access key {args.access_key_id} not found in this account", file=sys.stderr)
        return 1
    except ClientError as exc:
        print(f"error: IAM API call failed: {exc}", file=sys.stderr)
        return 1

    print(f"Deactivated {result.access_key_id} (owner: {result.user_name})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
