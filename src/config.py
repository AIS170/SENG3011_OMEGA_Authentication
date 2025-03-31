import os
from dotenv import load_dotenv
import boto3
from constants import REGION

load_dotenv()

ENVIRONMENT = os.environ.get('ENVIRONMENT', 'local')
CLIENT_ROLE_ARN = "arn:aws:iam::149536468960:role/shareDynamoDB"
CLIENT_DYNAMO_NAME = "authentication"

if ENVIRONMENT == 'testing':
    POOL_ID = "test-id"
    CLIENT_ID = "test-id"
    DB = "test-table"
    CLIENT_SECRET = "test-secret"
elif ENVIRONMENT == 'local':
    POOL_ID = os.environ.get("COGNITO_POOL_ID")
    CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID")
    DB = os.environ.get("DYNAMODB_TABLE")
    CLIENT_SECRET = os.environ.get("COGNITO_CLIENT_SECRET")
elif ENVIRONMENT == 'production':
    pass
    # Insert code to retrieve sensitive values from AWS ECS Secrets Manager


def put_item_to_auth_table(item: dict):
    sts_client = boto3.client('sts')

    # Assume the cross-account role
    assumed_role_object = sts_client.assume_role(
        RoleArn=CLIENT_ROLE_ARN,
        RoleSessionName='AssumeRoleSession1'
    )

    credentials = assumed_role_object['Credentials']

    # Create a session with the assumed credentials
    assumed_session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=REGION
    )

    # Use the session to create a DynamoDB resource
    dynamodb = assumed_session.resource('dynamodb')
    table = dynamodb.Table(CLIENT_DYNAMO_NAME)

    # Write to the table
    response = table.put_item(Item=item)
    return response