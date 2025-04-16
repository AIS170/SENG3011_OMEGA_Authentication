from src.auth import (
    sign_up,
    confirm_signup,
    admin_confirm_signup,
    login,
    logout,
    delete_user,
    generate_secret_hash,
    forgot_password,
    confirm_forgot_password,
    resend_confirmation_code,
    update_email,
    update_password,
    user_info
)


# =========================================================================== #
# SIGN-UP TESTS                                                               #
# =========================================================================== #

# Test successful signup with valid inputs
def test_signup(test_cognito, clear_dynamo):
    ret = sign_up(
        'jd101',
        'john.doe@gmail.com',
        'goodPassword123!',
        'John Doe'
    )

    assert ret['message'] == (
        'User registered successfully. Please check email for confirmation '
        'code'
    )
    assert 'user_sub' in ret


# Test for error upon signup with an already in use username
def test_username_in_use(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    ret = sign_up(
        'jd101',
        'jane.doe@gmail.com',
        'goodPassword123!',
        'Jane Doe'
    )

    assert 'error_code' in ret
    assert ret['error_code'] == 'UsernameExistsException'
    assert ret['message'] == (
        'The username is already in use.An error occurred '
        '(UsernameExistsException) when calling the SignUp operation: '
        'User already exists'
    )


# Test for error upon signup with a badly formatted password
def test_bad_password(test_cognito, clear_dynamo):
    ret = sign_up(
        'jd101',
        'john.doe@gmail.com',
        'badpassword',
        'John Doe'
    )

    assert 'error_code' in ret
    assert ret['error_code'] == 'InvalidPasswordException'
    assert ret['message'] == (
        'Invalid password provided.An error occurred '
        '(InvalidPasswordException) when calling the SignUp operation: '
        'Password did not conform with policy: Password must have uppercase '
        'characters'
    )


# Test for error upon signup with a badly formatted email
def test_bad_email(test_cognito, clear_dynamo):
    ret = sign_up(
        'jd101',
        'john.doe.example.com',
        'goodPassword123!',
        'John Doe'
    )

    assert 'error_code' in ret
    assert ret['error_code'] == 'InvalidEmail'
    assert ret['message'] == 'The provided email is in an invalid format'


# =========================================================================== #
# CONFIRM SIGN-UP TESTS                                                       #
# =========================================================================== #

# Test for successful admin confirm signup with valid inputs
def test_admin_confirm_signup(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')

    ret = admin_confirm_signup('jd101')

    assert ret['message'] == 'Confirmation successful'


# Test for error upon using admin route outside of a testing environment
def test_admin_confirm_signup_not_allowed(
    clear_dynamo,
    test_cognito,
    monkeypatch
):
    monkeypatch.setenv('TESTING', 'false')

    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')

    ret = admin_confirm_signup('jd101')

    assert 'error_code' in ret
    assert ret['error_code'] == 'MethodNotAllowed'
    assert ret['message'] == 'You are not authorised to perform this action.'


# Test for error upon using admin confirm signup for non existent user
def test_admin_confirm_signup_user_not_found(
    test_cognito,
    clear_dynamo
):
    ret = admin_confirm_signup('jd101')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotFoundException'
    assert ret['message'] == 'The user could not be found.'


# Test for error upon using admin confirm signup twice for a user
def test_admin_confirm_signup_user_already_confirmed(
    test_cognito,
    clear_dynamo
):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    ret = admin_confirm_signup('jd101')
    assert ret['message'] == 'Confirmation successful'

    ret = admin_confirm_signup('jd101')

    assert 'error_code' in ret
    assert ret['error_code'] == 'NoVerificationRequired'
    assert ret['message'] == 'User has already confirmed their email.'


# Test for successful confirm signup with mocked cognito response.
# Cognito response is mocked as there is no way to retrieve the confirmation
# code from an email during testing
def test_confirm_signup(test_cognito, clear_dynamo, monkeypatch):
    def test_confirmation(**kwargs):
        return {}

    monkeypatch.setattr(
        test_cognito['client'],
        'confirm_sign_up',
        test_confirmation
    )

    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')

    ret = confirm_signup('jd101', '123456')

    assert ret['message'] == 'Confirmation successful'


# Test for error upon using confirm signup on an already confirmed user
def test_confirm_signup_user_already_confirmed(
    test_cognito,
    clear_dynamo
):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    ret = admin_confirm_signup('jd101')
    assert ret['message'] == 'Confirmation successful'

    ret = confirm_signup('jd101')

    assert 'error_code' in ret
    assert ret['error_code'] == 'NoVerificationRequired'
    assert ret['message'] == 'User has already confirmed their email.'


# Test for error upon using confirm signup with invalid confirmation code
def test_confirm_signup_invalid_code(test_cognito, user_data_1, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')

    ret = confirm_signup('jd101', '123456')

    assert ret['message'] == 'The provided confirmation code has expired.'


# =========================================================================== #
# LOGIN TESTS                                                                 #
# =========================================================================== #

# Test for successful login with valid input
def test_login(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = login('jd101', 'goodPassword123!')

    assert ret['message'] == 'Login Successful'
    assert 'id_token' in ret
    assert 'access_token' in ret
    assert 'refresh_token' in ret


# Test for error upon logging in non existant user
def test_user_not_exist(test_cognito, clear_dynamo):
    ret = login('jd101', 'goodPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotFoundException'
    assert ret['message'] == 'The user could not be found.'


# Test for error upon logging in with incorrect password
def test_incorrect_password(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = login('jd101', 'goodPassword456!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'InvalidCredentials'
    assert ret['message'] == 'The username or password is incorrect.'


# Test for error upon logging into an unconfirmed account
def test_user_not_confirmed(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')

    ret = login('jd101', 'goodPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotConfirmedException'
    assert ret['message'] == 'User is not confirmed'


# =========================================================================== #
# LOGOUT TESTS                                                                #
# =========================================================================== #

# Test successful logout with valid inputs
def test_logout(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')
    access_token = login('jd101', 'goodPassword123!')['access_token']

    ret = logout(access_token)

    assert ret['message'] == 'Logout Successful!'


# Test for error upon logging out with invalid token
def test_logout_invalid_token(test_cognito, clear_dynamo):
    ret = logout('123')

    assert 'error_code' in ret
    assert ret['error_code'] == 'NotAuthorizedException'
    assert ret['message'] == 'You are not authorised to complete this action.'


# =========================================================================== #
# DELETE USER TESTS                                                           #
# =========================================================================== #

# Test successful user deletion with valid input
def test_delete_user(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = delete_user('jd101', 'goodPassword123!')

    assert ret['message'] == 'User jd101 deleted successfully'

    ret = login('jd101', 'goodPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotFoundException'
    assert ret['message'] == 'The user could not be found.'


# Test for error upon deleting non existant user
def test_delete_non_existing_user(test_cognito, clear_dynamo):
    ret = delete_user('jd101', 'goodPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotFoundException'
    assert ret['message'] == 'The user could not be found.'


# Test for error upon deleting user with incorrect password
def test_delete_user_incorrect_password(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = delete_user('jd101', 'incorrectPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'InvalidCredentials'
    assert ret['message'] == 'The password is incorrect.'


# Test for error upon deleting unconfirmed user
def test_delete_unconfirmed_user(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')

    ret = delete_user('jd101', 'incorrectPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotConfirmedException'
    assert ret['message'] == 'User is not confirmed'


# =========================================================================== #
# FORGOT PASSWORD TESTS                                                       #
# =========================================================================== #

# Test successful password reset
# Cognito response is mocked as there is no way to retrieve the confirmation
# code from an email during testing
def test_forgot_password(test_cognito, clear_dynamo, monkeypatch):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = forgot_password('jd101')

    assert ret['message'] == (
        'A confirmation code has been sent to your email to reset your '
        'password'
    )

    def test_confirm_forgot_password(**kwargs):
        assert kwargs['Username'] == 'jd101'
        assert kwargs['ConfirmationCode'] == '123456'
        assert kwargs['Password'] == 'greatPassword123!'
        return {}

    monkeypatch.setattr(
        test_cognito['client'],
        'confirm_forgot_password',
        test_confirm_forgot_password
    )

    ret = confirm_forgot_password('jd101', '123456', 'greatPassword123!')
    assert ret['message'] == 'Password has been reset successfully'


# Test for error on password reset with invalid username
def test_forgot_password_with_invalid_user(
    test_cognito,
    clear_dynamo
):
    ret = forgot_password('jd102')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotFoundException'
    assert ret['message'] == 'The user could not be found.'


# =========================================================================== #
# CONFIRM FORGOT PASSWORD TESTS                                               #
# =========================================================================== #

# Test for error on confirm password reset with invalid username
def test_confirm_forgot_password_with_invalid_user(
    test_cognito,
    clear_dynamo
):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')
    forgot_password('jd101')

    ret = confirm_forgot_password('jd102', '1234', 'greatPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotFoundException'
    assert ret['message'] == 'The user could not be found.'


# Test for error on confirm password reset with invalid confirmation code
def test_confirm_forgot_password_with_invalid_conf_code(
    test_cognito,
    clear_dynamo
):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')
    forgot_password('jd101')

    ret = confirm_forgot_password('jd101', '1234', 'greatPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'CodeMismatchException'
    assert ret['message'] == 'The provided confirmation code is incorrect.'


# =========================================================================== #
# RESEND CONFIRMATION CODE TESTS                                              #
# =========================================================================== #

# Test for successful confirmation code resend
def test_resend_confirmation_code(test_cognito_with_autoverify, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')

    ret = resend_confirmation_code('jd101')

    assert ret['message'] == (
        'A new confirmation code has been sent to your email'
    )


# Test error when resending confirmation code with invalid username
def test_resend_confirmation_code_invalid_user(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')

    ret = resend_confirmation_code('jd102')

    assert 'error_code' in ret
    assert ret['error_code'] == 'UserNotFoundException'
    assert ret['message'] == 'The user could not be found.'


# Test error when resending confirmation code for an already confirmed user
def test_resend_confirmation_code_for_confirmed_user(
    test_cognito,
    clear_dynamo
):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = resend_confirmation_code('jd101')

    assert 'error_code' in ret
    assert ret['error_code'] == 'NoVerificationRequired'
    assert ret['message'] == 'User has already confirmed their email.'


# =========================================================================== #
# UPDATE EMAIL TESTS                                                          #
# =========================================================================== #

# Test for successful email update
def test_update_email(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')
    access_token = login('jd101', 'goodPassword123!')['access_token']

    ret = update_email(access_token, 'john.doe101@gmail.com')

    assert ret['message'] == ('Email successfully updated.')

    ret = user_info(access_token)

    assert ret['message'] == 'User info retrieved successfully'
    assert ret['name'] == 'John Doe'
    assert ret['username'] == 'jd101'
    assert ret['email'] == 'john.doe101@gmail.com'


# Test for error when email is updated with invalid token
def test_update_email_invalid_token(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = update_email('12345', 'john.doe101@gmail.com')

    assert 'error_code' in ret
    assert ret['error_code'] == 'NotAuthorizedException'
    assert ret['message'] == 'You are not authorised to complete this action.'


# Test for error when email is updated with invalid email
def test_update_email_invalid_email(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')
    access_token = login('jd101', 'goodPassword123!')['access_token']

    ret = update_email(access_token, 'john.doe101.gmail.com')

    assert 'error_code' in ret
    assert ret['error_code'] == 'InvalidEmail'
    assert ret['message'] == 'The provided email is in an invalid format'


# =========================================================================== #
# UPDATE PASSWORD TESTS                                                       #
# =========================================================================== #

# Test for successful password update
def test_update_password(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')
    access_token = login('jd101', 'goodPassword123!')['access_token']

    ret = update_password(
        access_token,
        'goodPassword123!',
        'greatPassword123!'
    )

    assert ret['message'] == 'Password successfully updated.'


# Test for error when password is updated with invalid token
def test_update_password_invalid_token(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = update_password('12345', 'goodPassword123!', 'greatPassword123!')

    assert 'error_code' in ret
    assert ret['error_code'] == 'NotAuthorizedException'
    assert ret['message'] == 'You are not authorised to complete this action.'


# Test for error when password is updated with invalid new password
def test_update_email_invalid_new_password(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')
    access_token = login('jd101', 'goodPassword123!')['access_token']

    ret = update_password(access_token, 'goodPassword123!', 'badpassword')

    assert 'error_code' in ret
    assert ret['error_code'] == 'InvalidPasswordException'
    assert ret['message'] == 'The new password is of invalid format'


# Test for error when password is updated with invalid current password
def test_update_password_invalid_old_password(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')
    access_token = login('jd101', 'goodPassword123!')['access_token']

    ret = update_password(
        access_token,
        'goodPassword1234!',
        'greatPassword123!'
    )

    assert 'error_code' in ret
    assert ret['error_code'] == 'InvalidPasswordException'
    assert ret['message'] == (
        'The provided current password does not match the true current '
        'password'
    )


# =========================================================================== #
# USER INFO TESTS                                                             #
# =========================================================================== #

# Test for successfully retrieving user info
def test_user_info(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')
    access_token = login('jd101', 'goodPassword123!')['access_token']

    ret = user_info(access_token)

    assert ret['message'] == 'User info retrieved successfully'
    assert ret['name'] == 'John Doe'
    assert ret['username'] == 'jd101'
    assert ret['email'] == 'john.doe@gmail.com'


# Test for error when retrieving user info with invalid token
def test_user_info_invalid_token(test_cognito, clear_dynamo):
    sign_up('jd101', 'john.doe@gmail.com', 'goodPassword123!', 'John Doe')
    admin_confirm_signup('jd101')

    ret = user_info('12345')

    assert 'error_code' in ret
    assert ret['error_code'] == 'NotAuthorizedException'
    assert ret['message'] == 'You are not authorised to complete this action.'


# =========================================================================== #
# HELPER FUNCTION TESTS                                                       #
# =========================================================================== #

# Test for successful secret hash generation with mock values
def test_generate_secret_hash(test_cognito):
    username = 'test_user'
    id = 'test_client_id'
    secret = 'test_client_secret'

    expected = 'wUe5KByW4HIcqAZJI7v4J2ltYG5A5bAO5fw92jwba2M='
    actual = generate_secret_hash(username, id, secret)

    assert actual == expected
