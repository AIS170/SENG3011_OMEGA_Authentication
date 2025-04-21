import os
from dotenv import load_dotenv

ENVIRONMENT = os.environ.get("ENVIRONMENT", "local")

if ENVIRONMENT == "testing":
    load_dotenv(dotenv_path=".env.test")

    POOL_ID = "test-id"
    CLIENT_ID = "test-id"
    CLIENT_SECRET = "test-secret"
    DB = os.environ.get("DYNAMODB_TABLE")
    CLIENT_ROLE_ARN = os.environ.get("CLIENT_ROLE_ARN")
elif ENVIRONMENT == "local":
    load_dotenv(dotenv_path=".env.local")

    POOL_ID = os.environ.get("COGNITO_POOL_ID")
    CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID")
    CLIENT_SECRET = os.environ.get("COGNITO_CLIENT_SECRET")
    DB = os.environ.get("DYNAMODB_TABLE")
    CLIENT_ROLE_ARN = os.environ.get("CLIENT_ROLE_ARN")
elif ENVIRONMENT == "pipeline":
    POOL_ID = "test-id"
    CLIENT_ID = "test-id"
    CLIENT_SECRET = "test-secret"
    DB = os.getenv("DYNAMODB_TABLE")
    CLIENT_ROLE_ARN = os.getenv("CLIENT_ROLE_ARN")
elif ENVIRONMENT == "production":
    POOL_ID = os.getenv("COGNITO_POOL_ID")
    CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
    CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")
    DB = os.getenv("DYNAMODB_TABLE")
    CLIENT_ROLE_ARN = os.getenv("CLIENT_ROLE_ARN")
