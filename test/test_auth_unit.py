import boto3

from src.constants import REGION

from src.auth import (
    sign_up,
    confirm_signup,
    admin_confirm_signup,
    login,
    logout,
    delete_user,
    generate_secret_hash
)


def setup_mock_cognito():
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

    return {
        "client": client,
        "client_id": client_id,
        "client_secret": client_secret,
        "pool_id": pool_id
    }


def test_signup(mock_cognito, clear_dynamo_after_test):
    ret = sign_up(
        'jd101',
        'john.doe@example.com',
        'goodPassword123!',
        'John Doe'
    )

    assert ret['message'] == (
        'User registered successfully. Please check email for confirmation '
        'code'
    )
    assert 'user_sub' in ret


def test_admin_confirm_signup(mock_cognito, clear_dynamo_after_test):
    sign_up('jd101', 'john.doe@example.com', 'goodPassword123!', 'John Doe')

    ret = admin_confirm_signup('jd101')

    assert ret['message'] == 'Confirmation successfull'


def test_login(mock_cognito, clear_dynamo_after_test):
    sign_up('jd101', 'john.doe@example.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = login('jd101', 'goodPassword123!')
    print(ret)

    assert ret['message'] == 'Login Successful'
    assert 'id_token' in ret
    assert 'access_token' in ret
    assert 'refresh_token' in ret


def test_logout(mock_cognito, clear_dynamo_after_test):
    sign_up('jd101', 'john.doe@example.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')
    access_token = login('jd101', 'goodPassword123!')['access_token']

    ret = logout(access_token)

    assert ret['message'] == 'Logout Successful!'


def test_delete_user(mock_cognito, clear_dynamo_after_test):
    sign_up('jd101', 'john.doe@example.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = delete_user('jd101', 'goodPassword123!')

    assert ret['message'] == 'User jd101 deleted successfully'

    ret = login('jd101', 'goodPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotFoundException'
    assert ret['message'] == 'The user could not be found.'


def test_generate_secret_hash(mock_cognito):
    username = 'test_user'
    id = 'test_client_id'
    secret = 'test_client_secret'

    expected = 'wUe5KByW4HIcqAZJI7v4J2ltYG5A5bAO5fw92jwba2M='
    actual = generate_secret_hash(username, id, secret)

    assert actual == expected


def test_username_in_use(mock_cognito, clear_dynamo_after_test):
    sign_up('jd101', 'john.doe@example.com', 'goodPassword123!', 'John Doe')
    ret = sign_up(
        'jd101',
        'jane.doe@example.com',
        'goodPassword123!',
        'Jane Doe'
    )

    assert 'error_code' in ret
    assert ret['error_code'] == 'UsernameExistsException'
    assert ret['message'] == 'The username is already in use.'


def test_bad_password(mock_cognito, clear_dynamo_after_test):
    ret = sign_up(
        'jd101',
        'john.doe@example.com',
        'badpassword',
        'John Doe'
    )

    assert 'error_code' in ret
    assert ret['error_code'] == 'InvalidPasswordException'
    assert ret['message'] == 'Invalid password provided.'


def test_user_not_exist(mock_cognito, clear_dynamo_after_test):
    ret = login('jd101', 'goodPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotFoundException'
    assert ret['message'] == 'The user could not be found.'


def test_incorrect_password(mock_cognito, clear_dynamo_after_test):
    sign_up('jd101', 'john.doe@example.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = login('jd101', 'goodPassword456!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'NotAuthorizedException'
    assert ret['message'] == 'You are not authorised to complete this action.'


def test_user_not_confirmed(mock_cognito, clear_dynamo_after_test):
    sign_up('jd101', 'john.doe@example.com', 'goodPassword123!', 'John Doe')

    ret = login('jd101', 'goodPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotConfirmedException'
    assert ret['message'] == 'User is not confirmed'


def test_logout_invalid_token(mock_cognito, clear_dynamo_after_test):
    ret = logout('123')

    assert 'error_code' in ret
    assert ret['error_code'] == 'NotAuthorizedException'
    assert ret['message'] == 'You are not authorised to complete this action.'


def test_delete_non_existing_user(mock_cognito, clear_dynamo_after_test):
    ret = delete_user('jd101', 'goodPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotFoundException'
    assert ret['message'] == 'The user could not be found.'


def test_delete_user_incorrect_password(mock_cognito, clear_dynamo_after_test):
    sign_up('jd101', 'john.doe@example.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = delete_user('jd101', 'incorrectPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'NotAuthorizedException'
    assert ret['message'] == 'You are not authorised to complete this action.'


def test_admin_confirm_signup_not_allowed(
    clear_dynamo_after_test,
    mock_cognito,
    monkeypatch
):
    monkeypatch.setenv('TESTING', 'false')

    sign_up('jd101', 'john.doe@example.com', 'goodPassword123!', 'John Doe')

    ret = admin_confirm_signup('jd101')

    assert 'error_code' in ret
    assert ret['error_code'] == 'MethodNotAllowed'
    assert ret['message'] == 'You are not authorised to perform this action.'


def test_admin_confirm_signup_user_not_found(
    mock_cognito,
    clear_dynamo_after_test
):
    ret = admin_confirm_signup('jd101')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotFoundException'
    assert ret['message'] == 'The user could not be found.'


def test_confirm_signup(mock_cognito, clear_dynamo_after_test, monkeypatch):
    def mock_confirmation(**kwargs):
        return {}

    monkeypatch.setattr(mock_cognito, 'confirm_sign_up', mock_confirmation)

    sign_up('jd101', 'john.doe@example.com', 'goodPassword123!', 'John Doe')

    ret = confirm_signup('jd101', '123456')

    assert ret['message'] == 'Confirmation successfull'
