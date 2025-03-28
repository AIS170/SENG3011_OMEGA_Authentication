import json
import pytest
import boto3
from src.app import app
from moto import mock_aws
from src.constants import REGION
from unittest.mock import patch

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
        client_secret = pool_client_response["UserPoolClient"].get("ClientSecret")

        with patch("auth.CLIENT_ID", client_id), patch("auth.CLIENT_SECRET", client_secret), patch("auth.POOL_ID", pool_id), patch("auth.get_cognito", return_value=client):
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
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )

        table.wait_until_exists()

        with patch("auth.get_dynamo", return_value=table):
            yield table


def test_signup(client, mock_cognito, mock_dynamo):
    data = {
        "username": "jd101",
        "email": "john.doe@example.com",
        "password": "goodPassword123!",
        "name": "John Doe"
    }
    response = client.post('/signup', data=json.dumps(data), content_type='application/json')
    print("Response Data:", response.get_json())
    assert response.status_code == 200
    
    response = client.post("/admin/confirm_signup", data=json.dumps({"username": "jd101"}), content_type='application/json')
    print("Response Data:", response.get_json())
    assert response.status_code == 200


def test_login(client, mock_cognito, mock_dynamo):
    data = {
        "username": "jd101",
        "email": "john.doe@example.com",
        "password": "goodPassword123!",
        "name": "John Doe"
    }
    response = client.post('/signup', data=json.dumps(data), content_type='application/json')
    assert response.status_code == 200

    response = client.post("/admin/confirm_signup", data=json.dumps({"username": "jd101"}), content_type='application/json')
    assert response.status_code == 200
    
    response = client.post("/login", data=json.dumps({"username": "jd101", "password": "goodPassword123!"}), content_type='application/json')
    assert response.status_code == 200


def test_logout(client, mock_cognito, mock_dynamo):
    data = {
        "username": "jd101",
        "email": "john.doe@example.com",
        "password": "goodPassword123!",
        "name": "John Doe"
    }
    response = client.post('/signup', data=json.dumps(data), content_type='application/json')
    assert response.status_code == 200

    response = client.post("/admin/confirm_signup", data=json.dumps({"username": "jd101"}), content_type='application/json')
    assert response.status_code == 200
    
    response = client.post("/login", data=json.dumps({"username": "jd101", "password": "goodPassword123!"}), content_type='application/json')
    token = response.get_json().get("access_token")
    assert response.status_code == 200

    response = client.post("/logout", data=json.dumps({"AccessToken": token}), content_type='application/json')
    assert response.status_code == 200


def test_username_in_use(client, mock_cognito, mock_dynamo):
    data1 = {
        "username": "jd101",
        "email": "john.doe@example.com",
        "password": "goodPassword123!",
        "name": "John Doe"
    }
    response = client.post('/signup', data=json.dumps(data1), content_type='application/json')
    assert response.status_code == 200
    
    response = client.post("/admin/confirm_signup", data=json.dumps({"username": "jd101"}), content_type='application/json')
    assert response.status_code == 200

    data2 = {
        "username": "jd101",
        "email": "jane.doe@example.com",
        "password": "goodPassword123!",
        "name": "Jane Doe"
    }
    
    response = client.post('/signup', data=json.dumps(data2), content_type='application/json')
    assert response.status_code == 400
    assert response.json.get("message") == "The username is already in use."


def test_bad_password(client, mock_cognito, mock_dynamo):
    data1 = {
        "username": "jd101",
        "email": "john.doe@example.com",
        "password": "badpassword",
        "name": "John Doe"
    }
    response = client.post('/signup', data=json.dumps(data1), content_type='application/json')
    assert response.status_code == 400
    assert response.json.get("message") == "Invalid password provided."


def test_user_not_exist(client, mock_cognito, mock_dynamo):
    response = client.post("/login", data=json.dumps({"username": "jd101", "password": "goodPassword123!"}), content_type='application/json')
    assert response.status_code == 404
    assert response.json.get("message") == "The user could not be found."


def test_incorrect_password(client, mock_cognito, mock_dynamo):
    data1 = {
        "username": "jd101",
        "email": "john.doe@example.com",
        "password": "goodPassword123!",
        "name": "John Doe"
    }
    response = client.post('/signup', data=json.dumps(data1), content_type='application/json')
    assert response.status_code == 200
    
    response = client.post("/admin/confirm_signup", data=json.dumps({"username": "jd101"}), content_type='application/json')
    assert response.status_code == 200
    
    response = client.post("/login", data=json.dumps({"username": "jd101", "password": "goodPassword456!"}), content_type='application/json')
    assert response.status_code == 401
    assert response.json.get("message") == "You are not authorised to complete this action."


def test_user_not_confirmed(client, mock_cognito, mock_dynamo):
    data1 = {
        "username": "jd101",
        "email": "john.doe@example.com",
        "password": "goodPassword123!",
        "name": "John Doe"
    }
    response = client.post('/signup', data=json.dumps(data1), content_type='application/json')
    assert response.status_code == 200
    
    response = client.post("/login", data=json.dumps({"username": "jd101", "password": "goodPassword123!"}), content_type='application/json')
    assert response.status_code == 403
    assert response.json.get("message") == "User is not confirmed"


def test_logout_invalid_token(client, mock_cognito, mock_dynamo):
    response = client.post("/logout", data=json.dumps({"AccessToken": "123"}), content_type='application/json')
    assert response.status_code == 401
    assert response.json.get("message") == "You are not authorised to complete this action."


def test_delete_user(client, mock_cognito, mock_dynamo):
    data1 = {
        "username": "jd101",
        "email": "john.doe@example.com",
        "password": "goodPassword123!",
        "name": "John Doe"
    }
    response = client.post('/signup', data=json.dumps(data1), content_type='application/json')
    assert response.status_code == 200
    
    response = client.post("/admin/confirm_signup", data=json.dumps({"username": "jd101"}), content_type='application/json')
    assert response.status_code == 200
    
    response = client.delete('/delete_user', data=json.dumps({"username": "jd101", "password": "goodPassword123!"}), content_type='application/json')
    assert response.status_code == 200

    response = client.post("/login", data=json.dumps({"username": "jd101", "password": "goodPassword123!"}), content_type='application/json')
    assert response.status_code == 404
    assert response.json.get("message") == "The user could not be found."


def test_delete_non_existing_user(client, mock_cognito, mock_dynamo):
    response = client.delete('/delete_user', data=json.dumps({"username": "jd101", "password": "goodPassword123!"}), content_type='application/json')
    assert response.status_code == 404
    assert response.json.get("message") == "The user could not be found."


def test_delete_user_incorrect_password(client, mock_cognito, mock_dynamo):
    data1 = {
        "username": "jd101",
        "email": "john.doe@example.com",
        "password": "goodPassword123!",
        "name": "John Doe"
    }
    response = client.post('/signup', data=json.dumps(data1), content_type='application/json')
    assert response.status_code == 200
    
    response = client.post("/admin/confirm_signup", data=json.dumps({"username": "jd101"}), content_type='application/json')
    assert response.status_code == 200

    response = client.delete('/delete_user', data=json.dumps({"username": "jd101", "password": "incorrectPassword123!"}), content_type='application/json')
    assert response.status_code == 401
    assert response.json.get("message") == "You are not authorised to complete this action."


def test_admin_confirm_signup_not_allowed(client, mock_cognito, mock_dynamo, monkeypatch):
    monkeypatch.setenv("TESTING", "false")

    data = {
        "username": "jd101",
        "email": "john.doe@example.com",
        "password": "goodPassword123!",
        "name": "John Doe"
    }
    response = client.post('/signup', data=json.dumps(data), content_type='application/json')
    print("Response Data:", response.get_json())
    assert response.status_code == 200
    
    response = client.post("/admin/confirm_signup", data=json.dumps({"username": "jd101"}), content_type='application/json')
    print("Response Data:", response.get_json())
    assert response.status_code == 403
    assert response.json.get("message") == "You are not authorised to perform this action."


def test_admin_confirm_signup_user_not_found(client, mock_cognito, mock_dynamo, monkeypatch):    
    response = client.post("/admin/confirm_signup", data=json.dumps({"username": "jd101"}), content_type='application/json')
    print("Response Data:", response.get_json())
    assert response.status_code == 404
    assert response.json.get("message") == "The user could not be found."


def test_confirm_signup(client, mock_cognito, mock_dynamo, monkeypatch):
    def mock_confirmation(**kwargs):
        return {}

    monkeypatch.setattr(mock_cognito, "confirm_sign_up", mock_confirmation)

    mock_dynamo.put_item(
        Item={"userID": "test", "username": "jd101", "status": "UNCONFIRMED"}
    )

    response = client.post(
        "/confirm_signup", json={"username": "jd101", "conf_code": "123456"}
    )

    assert response.status_code == 200
