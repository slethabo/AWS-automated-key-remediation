import boto3
import re
from botocore.exceptions import ClientError

# Regex pattern matching standard AWS Access Key IDs
AWS_KEY_PATTERN = r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"

def find_key_owner(iam_client, access_key_id: str):
    """Enumerates IAM users to locate the owner of the target AccessKeyId."""
    paginator = iam_client.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            username = user['UserName']
            keys = iam_client.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in keys:
                if key['AccessKeyId'] == access_key_id:
                    return username
    return None

def deactivate_access_key(access_key_id: str):
    """Deactivates the target access key."""
    iam = boto3.client('iam')
    
    print(f"[i] Searching owner for key: {access_key_id}...")
    username = find_key_owner(iam, access_key_id)
    
    if not username:
        print(f"[!] Key {access_key_id} not found or inactive.")
        return False

    print(f"[+] Key found! Owned by user: '{username}'")
    
    try:
        iam.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status='Inactive'
        )
        print(f"[SUCCESS] Access key {access_key_id} has been deactivated!")
        return True
    except ClientError as e:
        print(f"[!] Boto3 Error: {e}")
        return False

if __name__ == "__main__":
    test_key = input("Enter Access Key ID to test deactivation: ").strip()
    if re.match(AWS_KEY_PATTERN, test_key):
        deactivate_access_key(test_key)
    else:
        print("[!] Invalid AWS Access Key format.")