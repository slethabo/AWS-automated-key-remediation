import json
import re
import boto3
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

def lambda_handler(event, context):
    """
    Lambda entry point. Expects an event containing the target access key ID.
    Example event input: {"access_key_id": "AKIA..."}
    """
    iam = boto3.client('iam')
    
    # Extract access key ID from event payload
    target_key = event.get('access_key_id') or event.get('AccessKeyId')
    
    if not target_key:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'No access_key_id provided in event.'})
        }
    
    target_key = target_key.strip()
    
    # Validate format
    if not re.match(AWS_KEY_PATTERN, target_key):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Invalid AWS Access Key format.'})
        }
        
    print(f"[i] Searching owner for key: {target_key}")
    username = find_key_owner(iam, target_key)
    
    if not username:
        print(f"[!] Key {target_key} not found or inactive.")
        return {
            'statusCode': 440,
            'body': json.dumps({'message': f'Key {target_key} not found.'})
        }

    print(f"[+] Key found! Owned by user: '{username}'")
    
    try:
        iam.update_access_key(
            UserName=username,
            AccessKeyId=target_key,
            Status='Inactive'
        )
        print(f"[SUCCESS] Access key {target_key} deactivated.")
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Successfully deactivated key {target_key}',
                'user': username
            })
        }
    except ClientError as e:
        print(f"[!] Boto3 Error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }