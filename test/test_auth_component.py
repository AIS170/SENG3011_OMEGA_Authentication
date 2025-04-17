import json


# =========================================================================== #
# SIGN-UP TESTS                                                               #
# =========================================================================== #

# Test successful signup with valid inputs
def test_signup(client, test_cognito, user_data_1, clear_dynamo):
    response = client.post(
        '/signup', data=json.dumps(user_data_1),
        content_type='application/json'
    )

    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200


# Test for error upon signup with missing input fields
def test_signup_bad_input(client, test_cognito, user_data_1, clear_dynamo):
    data = {
        'email': 'john.doe@gmail.com',
        'password': 'goodPassword123!',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup', data=json.dumps(data),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'All fields must be provided (username, email, password, name)'
    )


# Test for error upon signup with an already in use username
def test_username_in_use(
    client,
    test_cognito,
    user_data_1,
    user_data_2,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/signup',
        data=json.dumps(user_data_2),
        content_type='application/json'
    )
    assert response.status_code == 400
    assert response.json.get('message') == (
        'The username is already in use.An error occurred '
        '(UsernameExistsException) when calling the SignUp operation: '
        'User already exists'
    )


# Test for error upon signup with a badly formatted password
def test_bad_password(client, test_cognito, clear_dynamo):
    data = {
        'username': 'jd101',
        'email': 'john.doe@gmail.com',
        'password': 'badpassword',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup',
        data=json.dumps(data),
        content_type='application/json'
    )
    assert response.status_code == 400
    assert response.json.get('message') == (
        'Invalid password provided.An error occurred '
        '(InvalidPasswordException) when calling the SignUp operation: '
        'Password did not conform with policy: Password must have uppercase '
        'characters'
    )


# Test for error upon signup with a badly formatted email
def test_bad_email(client, test_cognito, clear_dynamo):
    data = {
        'username': 'jd101',
        'email': 'john.doe.example.com',
        'password': 'goodPassword123!',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup',
        data=json.dumps(data),
        content_type='application/json'
    )
    assert response.status_code == 400
    assert response.json.get('message') == (
        'The provided email is in an invalid format'
    )


# =========================================================================== #
# CONFIRM SIGN-UP TESTS                                                       #
# =========================================================================== #

# Test for error upon using admin route outside of a testing environment
def test_admin_confirm_signup_not_allowed(
    client,
    test_cognito,
    monkeypatch,
    user_data_1,
    clear_dynamo
):
    monkeypatch.setenv('TESTING', 'false')

    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 403
    assert response.json.get('message') == (
        'You are not authorised to perform this action.'
    )


# Test for error upon using admin confirm signup with missing input fields
def test_admin_confirm_signup_bad_input(
    client,
    test_cognito,
    user_data_1,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({}),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'All fields must be provided (username)'
    )


# Test for error upon using admin confirm signup for non existent user
def test_admin_confirm_signup_user_not_found(
    client,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': 'jd101'}),
        content_type='application/json'
    )
    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


# Test for error upon using admin confirm signup twice for a user
def test_admin_confirm_signup_user_already_confirmed(
    client,
    test_cognito,
    user_data_1,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'User has already confirmed their email.'
    )


# Test for successful confirm signup with mocked cognito response.
# Cognito response is mocked as there is no way to retrieve the confirmation
# code from an email during testing
def test_confirm_signup(
    client,
    test_cognito,
    monkeypatch,
    user_data_1,
    clear_dynamo
):
    def test_confirmation(**kwargs):
        return {}
    monkeypatch.setattr(
        test_cognito['client'],
        'confirm_sign_up',
        test_confirmation
    )

    response = client.post(
        '/signup', data=json.dumps(user_data_1),
        content_type='application/json'
    )

    response = client.post(
        '/confirm_signup',
        json={'username': user_data_1['username'], 'conf_code': '123456'}
    )
    assert response.status_code == 200


# Test for error upon using confirm signup with missing input fields
def test_confirm_signup_bad_input(
    client,
    test_cognito,
    user_data_1,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'All fields must be provided (username, conf_code)'
    )


# Test for error upon using confirm signup with invalid confirmation code
def test_confirm_signup_invalid_code(
    client,
    test_cognito,
    user_data_1,
    clear_dynamo
):
    response = client.post(
        '/signup', data=json.dumps(user_data_1),
        content_type='application/json'
    )

    response = client.post(
        '/confirm_signup',
        json={'username': user_data_1['username'], 'conf_code': '123456'}
    )
    assert response.status_code == 400
    assert response.json.get('message') == (
        'The provided confirmation code is incorrect.'
    )


# Test for error upon using confirm signup on an already confirmed user
def test_confirm_signup_user_already_confirmed(
    client,
    test_cognito,
    user_data_1,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/confirm_signup',
        data=json.dumps({
            'username': user_data_1['username'],
            'conf_code': '12345'
        }),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'User has already confirmed their email.'
    )


# =========================================================================== #
# LOGIN TESTS                                                                 #
# =========================================================================== #

# Test for successful login with valid input
def test_login(client, test_cognito, user_data_1, clear_dynamo):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    assert response.status_code == 200


# Test for error upon logging in with missing input fields
def test_login_bad_input(client, test_cognito, user_data_1, clear_dynamo):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 400
    assert response.json.get('message') == (
        'All fields must be provided (username, password)'
    )


# Test for error upon logging in non existant user
def test_user_not_exist(client, test_cognito, clear_dynamo):
    response = client.post(
        '/login',
        data=json.dumps({'username': 'jd101', 'password': 'goodPassword123!'}),
        content_type='application/json'
    )
    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


# Test for error upon logging in with incorrect password
def test_incorrect_password(client, test_cognito, user_data_1, clear_dynamo):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': 'goodPassword456!'
            }
        ),
        content_type='application/json'
    )
    assert response.status_code == 401
    assert response.json.get('message') == (
        'The username or password is incorrect.'
    )


# Test for error upon logging into an unconfirmed account
def test_user_not_confirmed(client, test_cognito, user_data_1, clear_dynamo):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    assert response.status_code == 403
    assert response.json.get('message') == 'User is not confirmed'


# =========================================================================== #
# LOGOUT TESTS                                                                #
# =========================================================================== #

# Test successful logout with valid inputs
def test_logout(client, test_cognito, user_data_1, clear_dynamo):
    response = client.post(
        '/signup', data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    token = response.get_json().get('access_token')
    assert response.status_code == 200

    response = client.post(
        '/logout',
        headers={'Authorization': f'Bearer {token}'},
        content_type='application/json'
    )
    assert response.status_code == 200


# Test for error upon logout with no token
def test_logout_no_token(client, test_cognito, user_data_1, clear_dynamo):
    response = client.post(
        '/signup', data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/logout',
        headers={'Authorization': ''},
        content_type='application/json'
    )
    assert response.status_code == 401
    assert response.json.get('message') == 'Access token is invalid.'


# Test for error upon logging out with invalid token
def test_logout_invalid_token(client, test_cognito, clear_dynamo):
    response = client.post(
        '/logout',
        headers={'Authorization': 'Bearer 123'},
        content_type='application/json'
    )
    assert response.status_code == 401
    assert response.json.get('message') == (
        'You are not authorised to complete this action.'
    )


# =========================================================================== #
# DELETE USER TESTS                                                           #
# =========================================================================== #

# Test successful user deletion with valid input
def test_delete_user(client, test_cognito, user_data_1, clear_dynamo):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.delete(
        '/delete_user',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


# Test for error upon deleting user with missing input fields
def test_delete_user_bad_input(
    client,
    test_cognito,
    user_data_1,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.delete(
        '/delete_user',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 400
    assert response.json.get('message') == (
        'All fields must be provided (username, password)')


# Test for error upon deleting non existant user
def test_delete_non_existing_user(client, test_cognito, clear_dynamo):
    response = client.delete(
        '/delete_user',
        data=json.dumps({'username': 'jd101', 'password': 'goodPassword123!'}),
        content_type='application/json'
    )
    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


# Test for error upon deleting user with incorrect password
def test_delete_user_incorrect_password(
    client,
    test_cognito,
    user_data_1,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.delete(
        '/delete_user',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': 'incorrectPassword123!'
            }
        ),
        content_type='application/json'
    )
    assert response.status_code == 401
    assert response.json.get('message') == ('The password is incorrect.')


# Test for error upon deleting unconfirmed user
def test_delete_unconfirmed_user(
    client,
    test_cognito,
    user_data_1,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.delete(
        '/delete_user',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': 'incorrectPassword123!'
            }
        ),
        content_type='application/json'
    )
    assert response.status_code == 403
    assert response.json.get('message') == 'User is not confirmed'


# =========================================================================== #
# FORGOT PASSWORD TESTS                                                       #
# =========================================================================== #

# Test successful password reset
# Cognito response is mocked as there is no way to retrieve the confirmation
# code from an email during testing
def test_forgot_password(
    client,
    test_cognito,
    user_data_1,
    clear_dynamo,
    monkeypatch
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    def mock_forgot_password(**kwargs):
        assert kwargs['Username'] == user_data_1['username']
        return {}

    monkeypatch.setattr(
        test_cognito['client'],
        'forgot_password',
        mock_forgot_password
    )

    response = client.post(
        '/forgot_password',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    assert response.json.get('message') == (
        'A confirmation code has been sent to your email to reset your '
        'password'
    )

    def mock_confirm_forgot_password(**kwargs):
        assert kwargs['Username'] == user_data_1['username']
        assert kwargs['ConfirmationCode'] == '123456'
        assert kwargs['Password'] == 'greatPassword123!'
        return {}

    monkeypatch.setattr(
        test_cognito['client'],
        'confirm_forgot_password',
        mock_confirm_forgot_password
    )

    response = client.post(
        '/confirm_forgot_password',
        data=json.dumps({
            'username': user_data_1['username'],
            'conf_code': '123456',
            'new_password': 'greatPassword123!'
        }),
        content_type='application/json'
    )

    assert response.status_code == 200
    assert response.json.get('message') == (
        'Password has been reset successfully'
    )


# Test for error on password reset with bad inputs
def test_forgot_password_bad_input(
    client,
    test_cognito,
    user_data_1,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/forgot_password',
        data=json.dumps({'username': None}),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'All fields must be provided (username)'
    )


# Test for error on password reset with invalid username
def test_forgot_password_with_invalid_user(
    client,
    user_data_1,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/forgot_password',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )

    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


# =========================================================================== #
# CONFIRM FORGOT PASSWORD TESTS                                               #
# =========================================================================== #

# Test for error on confirm password reset with invalid username
def test_confirm_forgot_password_bad_input(
    client,
    user_data_1,
    test_cognito,
    clear_dynamo,
    monkeypatch
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    def mock_forgot_password(**kwargs):
        assert kwargs['Username'] == user_data_1['username']
        return {}

    monkeypatch.setattr(
        test_cognito['client'],
        'forgot_password',
        mock_forgot_password
    )

    response = client.post(
        '/forgot_password',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/confirm_forgot_password',
        data=json.dumps({
            'username': None,
            'conf_code': '123456',
            'new_password': user_data_1['password']
        }),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'All fields must be provided (username, conf_code, new_password)'
    )


# Test for error on confirm password reset with invalid username
def test_confirm_forgot_password_with_invalid_user(
    client,
    user_data_1,
    test_cognito,
    clear_dynamo,
    monkeypatch
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    def mock_forgot_password(**kwargs):
        assert kwargs['Username'] == user_data_1['username']
        return {}

    monkeypatch.setattr(
        test_cognito['client'],
        'forgot_password',
        mock_forgot_password
    )

    response = client.post(
        '/forgot_password',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/confirm_forgot_password',
        data=json.dumps({
            'username': 'jd102',
            'conf_code': '123456',
            'new_password': user_data_1['password']
        }),
        content_type='application/json'
    )

    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


# Test for error on confirm password reset with invalid confirmation code
def test_confirm_forgot_password_with_invalid_conf_code(
    client,
    user_data_1,
    test_cognito,
    clear_dynamo,
    monkeypatch
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    def mock_forgot_password(**kwargs):
        assert kwargs['Username'] == user_data_1['username']
        return {}

    monkeypatch.setattr(
        test_cognito['client'],
        'forgot_password',
        mock_forgot_password
    )

    response = client.post(
        '/forgot_password',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/confirm_forgot_password',
        data=json.dumps({
            'username': user_data_1['username'],
            'conf_code': '123456',
            'new_password': user_data_1['password']
        }),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'The provided confirmation code is incorrect.'
    )


# =========================================================================== #
# RESEND CONFIRMATION CODE TESTS                                              #
# =========================================================================== #

# Test for successful confirmation code resend
def test_resend_confirmation_code(
    client,
    user_data_1,
    test_cognito,
    clear_dynamo,
    monkeypatch
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    def mock_resend_confirmation_code(**kwargs):
        assert kwargs['ClientId']
        assert kwargs['SecretHash']
        assert kwargs['Username'] == 'jd101'
        return {}

    monkeypatch.setattr(
        test_cognito['client'],
        'resend_confirmation_code',
        mock_resend_confirmation_code
    )

    response = client.post(
        '/resend_confirmation_code',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )

    assert response.status_code == 200
    assert response.json.get('message') == (
        'A new confirmation code has been sent to your email'
    )


# Test for error when resending confirmation code with bad input
def test_resend_confirmation_code_bad_input(
    client,
    user_data_1,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/resend_confirmation_code',
        data=json.dumps({'username': None}),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'All fields must be provided (username)'
    )


# Test error when resending confirmation code with invalid username
def test_resend_confirmation_code_invalid_user(
    client,
    user_data_1,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    print(response)
    assert response.status_code == 200

    response = client.post(
        '/resend_confirmation_code',
        data=json.dumps({'username': 'jd102'}),
        content_type='application/json'
    )

    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


# Test error when resending confirmation code for an already confirmed user
def test_resend_confirmation_code_for_confirmed_user(
    client,
    user_data_1,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/resend_confirmation_code',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'User has already confirmed their email.'
    )


# =========================================================================== #
# UPDATE EMAIL TESTS                                                          #
# =========================================================================== #

# Test for successful email update
def test_update_email(user_data_1, client, test_cognito, clear_dynamo):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    token = response.get_json().get('access_token')

    response = client.put(
        '/update_email',
        headers={'Authorization': f'Bearer {token}'},
        data=json.dumps({'new_email': 'john.doe101@gmail.com'}),
        content_type='application/json'
    )

    assert response.status_code == 200
    assert response.json.get('message') == 'Email successfully updated.'

    response = client.get(
        '/user_info',
        headers={'Authorization': f'Bearer {token}'},
        content_type='application/json'
    )

    assert response.status_code == 200
    assert response.json.get('name') == user_data_1['name']
    assert response.json.get('username') == user_data_1['username']
    assert response.json.get('email') == 'john.doe101@gmail.com'


# Test for error when email is updated with bad input
def test_update_email_bad_inputs(
    user_data_1,
    client,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    token = response.get_json().get('access_token')

    response = client.put(
        '/update_email',
        headers={'Authorization': f'Bearer {token}'},
        data=json.dumps({'new_email': None}),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'All fields must be provided (new_email)'
    )


# Test for error when email is updated with invalid token
def test_update_email_invalid_token(
    user_data_1,
    client,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.put(
        '/update_email',
        headers={'Authorization': 'Bearer 12345'},
        data=json.dumps({'new_email': 'john.doe101@gmail.com'}),
        content_type='application/json'
    )

    assert response.status_code == 401
    assert response.json.get('message') == (
        'You are not authorised to complete this action.'
    )


# Test for error when email is updated with invalid email
def test_update_email_invalid_email(
    user_data_1,
    client,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    token = response.get_json().get('access_token')

    response = client.put(
        '/update_email',
        headers={'Authorization': f'Bearer {token}'},
        data=json.dumps({'new_email': 'john.doe101.gmail.com'}),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'The provided email is in an invalid format'
    )


# =========================================================================== #
# UPDATE PASSWORD TESTS                                                       #
# =========================================================================== #

# Test for successful password update
def test_update_password(user_data_1, client, test_cognito, clear_dynamo):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    token = response.get_json().get('access_token')

    response = client.put(
        '/update_password',
        headers={'Authorization': f'Bearer {token}'},
        data=json.dumps({
            'old_password': user_data_1['password'],
            'new_password': 'greatPassword123!'
        }),
        content_type='application/json'
    )

    assert response.status_code == 200
    assert response.json.get('message') == 'Password successfully updated.'


# Test for error when password is updated with bad inputs
def test_update_password_bad_input(
    user_data_1,
    client,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    token = response.get_json().get('access_token')

    response = client.put(
        '/update_password',
        headers={'Authorization': f'Bearer {token}'},
        data=json.dumps({
            'old_password': user_data_1['password'],
            'new_password': None
        }),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'All fields must be provided (old_password, new_password)'
    )


# Test for error when password is updated with no token
def test_update_password_no_token(
    user_data_1,
    client,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.put(
        '/update_password',
        headers={'Authorization': ''},
        data=json.dumps({
            'old_password': user_data_1['password'],
            'new_password': 'greatPassword123!'
        }),
        content_type='application/json'
    )

    assert response.status_code == 401
    assert response.json.get('message') == 'Access token is invalid.'


# Test for error when password is updated with invalid token
def test_update_password_invalid_token(
    user_data_1,
    client,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.put(
        '/update_password',
        headers={'Authorization': 'Bearer 12345'},
        data=json.dumps({
            'old_password': user_data_1['password'],
            'new_password': 'greatPassword123!'
        }),
        content_type='application/json'
    )

    assert response.status_code == 401
    assert response.json.get('message') == (
        'You are not authorised to complete this action.'
    )


# Test for error when password is updated with invalid new password
def test_update_email_invalid_new_password(
    user_data_1,
    client,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    token = response.get_json().get('access_token')

    response = client.put(
        '/update_password',
        headers={'Authorization': f'Bearer {token}'},
        data=json.dumps({
            'old_password': user_data_1['password'],
            'new_password': 'badpassword'
        }),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'The new password is of invalid format'
    )


# Test for error when password is updated with invalid current password
def test_update_password_invalid_old_password(
    user_data_1,
    client,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    token = response.get_json().get('access_token')

    response = client.put(
        '/update_password',
        headers={'Authorization': f'Bearer {token}'},
        data=json.dumps({
            'old_password': 'goodPassword1234!',
            'new_password': 'greatPassword123!'
        }),
        content_type='application/json'
    )

    assert response.status_code == 400
    assert response.json.get('message') == (
        'The provided current password does not match the true current '
        'password'
    )


# =========================================================================== #
# USER INFO TESTS                                                             #
# =========================================================================== #

# Test for successfully retrieving user info
def test_user_info(user_data_1, client, test_cognito, clear_dynamo):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps(
            {
                'username': user_data_1['username'],
                'password': user_data_1['password']
            }
        ),
        content_type='application/json'
    )
    token = response.get_json().get('access_token')

    response = client.get(
        '/user_info',
        headers={'Authorization': f'Bearer {token}'},
        content_type='application/json'
    )

    assert response.status_code == 200
    assert response.json.get('message') == 'User info retrieved successfully'
    assert response.json.get('name') == user_data_1['name']
    assert response.json.get('username') == user_data_1['username']
    assert response.json.get('email') == user_data_1['email']


# Test for error when retrieving user info with no token
def test_user_info_no_token(user_data_1, client, test_cognito, clear_dynamo):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.get(
        '/user_info',
        headers={'Authorization': ''},
        content_type='application/json'
    )

    assert response.status_code == 401
    assert response.json.get('message') == 'Access token is invalid.'


# Test for error when retrieving user info with invalid token
def test_user_info_invalid_token(
    user_data_1,
    client,
    test_cognito,
    clear_dynamo
):
    response = client.post(
        '/signup',
        data=json.dumps(user_data_1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': user_data_1['username']}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.get(
        '/user_info',
        headers={'Authorization': 'Bearer 12345'},
        content_type='application/json'
    )

    assert response.status_code == 401
    assert response.json.get('message') == (
        'You are not authorised to complete this action.'
    )
