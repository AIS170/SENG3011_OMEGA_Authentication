from unittest.mock import patch
import boto3
import pytest

from src.config import DB
from src.app import app
from src.constants import REGION


@pytest.fixture
def client():
    with app.test_client() as client:
        yield client


@pytest.fixture(scope="function")
def test_cognito():
    client = boto3.client("cognito-idp", region_name=REGION)

    pool = client.create_user_pool(
        PoolName="testPool",
        AutoVerifiedAttributes=[],
    )
    pool_id = pool["UserPool"]["Id"]

    pool_client_response = client.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName="testClient",
        GenerateSecret=True,
        ExplicitAuthFlows=["USER_PASSWORD_AUTH"],
    )

    client_id = pool_client_response["UserPoolClient"]["ClientId"]
    client_secret = pool_client_response["UserPoolClient"].get("ClientSecret")

    with (
        patch("src.auth.CLIENT_ID", client_id),
        patch("src.auth.CLIENT_SECRET", client_secret),
        patch("src.auth.POOL_ID", pool_id),
        patch("src.auth.get_cognito", return_value=client),
    ):
        yield {
            "client": client,
            "user_pool_id": pool_id,
        }

    client.delete_user_pool(UserPoolId=pool_id)


@pytest.fixture(scope="function")
def clear_dynamo():
    yield

    dynamo_client = boto3.resource("dynamodb", REGION)
    table = dynamo_client.Table(DB)

    ret = table.scan()
    for item in ret.get("Items", []):
        table.delete_item(Key={"userID": item["userID"]})


@pytest.fixture
def user_data_1():
    return {
        "username": "jd101",
        "email": "john.doe@gmail.com",
        "password": "goodPassword123!",
        "name": "John Doe",
    }


@pytest.fixture
def user_data_2():
    return {
        "username": "jd101",
        "email": "jane.doe@gmail.com",
        "password": "goodPassword123!",
        "name": "Jane Doe",
    }
