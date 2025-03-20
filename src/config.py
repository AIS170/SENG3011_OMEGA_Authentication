import os
from dotenv import load_dotenv

load_dotenv()

REGION = os.getenv("AWS_REGION")
POOL_ID = os.getenv("COGNITO_POOL_ID")
CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
DB = os.getenv("DYNAMODB_TABLE")
CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")
