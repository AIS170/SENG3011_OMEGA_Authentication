import os
from dotenv import load_dotenv

load_dotenv()

ENVIRONMENT = os.environ.get('ENVIRONMENT', 'local')

if ENVIRONMENT == 'testing':
    POOL_ID = "test-id"
    CLIENT_ID = "test-id"
    DB = "test-table"
    CLIENT_SECRET = "test-secret"
    CLIENT_ROLE_ARN = "test-client-ARN"
elif ENVIRONMENT == 'local':
    POOL_ID = os.environ.get("COGNITO_POOL_ID")
    CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID")
    DB = os.environ.get("DYNAMODB_TABLE")
    CLIENT_SECRET = os.environ.get("COGNITO_CLIENT_SECRET")
    CLIENT_ROLE_ARN = os.environ.get("CLIENT_ROLE_ARN")
elif ENVIRONMENT == 'production':
    pass
    # Insert code to retrieve sensitive values from AWS ECS Secrets Manager
