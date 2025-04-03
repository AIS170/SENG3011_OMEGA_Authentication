from unittest.mock import patch
import boto3
from moto import mock_aws
import pytest

from src.app import app
from src.constants import REGION


@pytest.fixture
def client():
    with app.test_client() as client:
        yield client


@pytest.fixture(scope="function")
def mock_cognito():
    with mock_aws():
        client = boto3.client("cognito-idp", region_name=REGION)

        pool = client.create_user_pool(PoolName="mockPool")
        pool_id = pool["UserPool"]["Id"]

        pool_client_response = client.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName="mockClient",
            GenerateSecret=True
        )

        client_id = pool_client_response["UserPoolClient"]["ClientId"]
        client_secret = pool_client_response["UserPoolClient"].get(
            "ClientSecret"
        )

        with patch("src.auth.CLIENT_ID", client_id), \
             patch("src.auth.CLIENT_SECRET", client_secret), \
             patch("src.auth.POOL_ID", pool_id), \
             patch("src.auth.get_cognito", return_value=client):
            yield client


@pytest.fixture(scope="function")
def mock_dynamo():
    with mock_aws():
        client = boto3.resource("dynamodb", region_name=REGION)

        table = client.create_table(
            TableName="mockDB",
            KeySchema=[
                {"AttributeName": "userID", "KeyType": "HASH"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "userID", "AttributeType": "S"}
            ],
            ProvisionedThroughput={
                "ReadCapacityUnits": 5,
                "WriteCapacityUnits": 5
            },
        )

        table.wait_until_exists()

        with patch("src.auth.get_dynamo", return_value=table):
            yield table
