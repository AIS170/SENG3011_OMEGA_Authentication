from src.auth import sign_up, confirm_signup, admin_confirm_signup, login, logout, delete_user, generate_secret_hash, get_dynamo, get_cognito

def test_signup(mock_cognito, mock_dynamo):
    ret = sign_up("jd101", "john.doe@example.com", "goodPassword123!", "John Doe")
    
    assert ret["message"] == (
        "User registered successfully. Please check email for confirmation "
        "code"
    )
    assert "user_sub" in ret


def test_admin_confirm_signup(mock_cognito, mock_dynamo):
    sign_up("jd101", "john.doe@example.com", "goodPassword123!", "John Doe")

    ret = admin_confirm_signup("jd101")

    assert ret["message"] == "Confirmation successfull"


def test_login(mock_cognito, mock_dynamo):
    sign_up("jd101", "john.doe@example.com", "goodPassword123!", "John Doe")
    admin_confirm_signup("jd101")
    
    ret = login("jd101", "goodPassword123!")

    assert ret["message"] == "Login Successful"
    assert "id_token" in ret
    assert "access_token" in ret
    assert "refresh_token" in ret


def test_logout(mock_cognito, mock_dynamo):
    sign_up("jd101", "john.doe@example.com", "goodPassword123!", "John Doe")
    admin_confirm_signup("jd101")
    access_token = login("jd101", "goodPassword123!")["access_token"]

    ret = logout(access_token)

    assert ret["message"] == "Logout Successful!"


def test_delete_user(mock_cognito, mock_dynamo):
    sign_up("jd101", "john.doe@example.com", "goodPassword123!", "John Doe")
    admin_confirm_signup("jd101")

    ret = delete_user("jd101", "goodPassword123!")

    assert ret["message"] == "User jd101 deleted successfully"


def test_generate_secret_hash():
    username = "test_user"
    id = "test_client_id"
    secret = "test_client_secret"

    expected = "wUe5KByW4HIcqAZJI7v4J2ltYG5A5bAO5fw92jwba2M="
    actual = generate_secret_hash(username, id, secret)

    assert actual == expected


def test_username_in_use(mock_cognito, mock_dynamo):
    sign_up("jd101", "john.doe@example.com", "goodPassword123!", "John Doe")
    ret = sign_up("jd101", "jane.doe@example.com", "goodPassword123!", "Jane Doe")
    
    assert "error_code" in ret
    assert ret["error_code"] == "UsernameExistsException"
    assert ret["message"] == "The username is already in use."


def test_bad_password(mock_cognito, mock_dynamo):
    ret = sign_up("jd101", "john.doe@example.com", "badpassword", "John Doe")
    
    assert "error_code" in ret
    assert ret["error_code"] == "InvalidPasswordException"
    assert ret["message"] == "Invalid password provided."


def test_user_not_exist(mock_cognito, mock_dynamo):
    ret = login("jd101", "goodPassword123!")

    assert "error_code" in ret
    assert ret["error_code"] == "UserNotFoundException"
    assert ret["message"] == "The user could not be found."


def test_incorrect_password(mock_cognito, mock_dynamo):
    sign_up("jd101", "john.doe@example.com", "badpassword", "John Doe")
    admin_confirm_signup("jd101")
    
    ret = login("jd101", "goodPassword123!")

    assert "error_code" in ret
    assert ret["error_code"] == "NotAuthorizedException"
    assert ret["message"] == "You are not authorised to complete this action."