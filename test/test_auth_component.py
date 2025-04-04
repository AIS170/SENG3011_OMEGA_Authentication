import json


# =========================================================================== #
# SIGN-UP TESTS                                                               #
# =========================================================================== #

# Test successfull signup with valid inputs
def test_signup(client, mock_cognito, user_data_1, clear_dynamo):
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
def test_signup_bad_input(client, mock_cognito, user_data_1, clear_dynamo):
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
    mock_cognito,
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
    assert response.json.get('message') == 'The username is already in use.'


# Test for error upon signup with a badly formatted password
def test_bad_password(client, mock_cognito, clear_dynamo):
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
    assert response.json.get('message') == 'Invalid password provided.'


# Test for error upon signup with a badly formatted email
def test_bad_email(client, mock_cognito, clear_dynamo):
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
    mock_cognito,
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
    mock_cognito,
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
    mock_cognito,
    clear_dynamo
):
    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': 'jd101'}),
        content_type='application/json'
    )
    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


# Test for successfull confirm signup with mocked cognito response.
# Cognito response is mocked as there is no way to retrieve the confirmation
# code from an email during testing
def test_confirm_signup(
    client,
    mock_cognito,
    monkeypatch,
    user_data_1,
    clear_dynamo
):
    def mock_confirmation(**kwargs):
        return {}
    monkeypatch.setattr(
        mock_cognito['client'],
        'confirm_sign_up',
        mock_confirmation
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
    mock_cognito,
    monkeypatch,
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
    mock_cognito,
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
        'The provided confirmation code has expired.'
    )


# =========================================================================== #
# LOGIN TESTS                                                                 #
# =========================================================================== #

# Test for successfull login with valid input
def test_login(client, mock_cognito, user_data_1, clear_dynamo):
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
def test_login_bad_input(client, mock_cognito, user_data_1, clear_dynamo):
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
def test_user_not_exist(client, mock_cognito, clear_dynamo):
    response = client.post(
        '/login',
        data=json.dumps({'username': 'jd101', 'password': 'goodPassword123!'}),
        content_type='application/json'
    )
    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


# Test for error upon logging in with incorrect password
def test_incorrect_password(client, mock_cognito, user_data_1, clear_dynamo):
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
def test_user_not_confirmed(client, mock_cognito, user_data_1, clear_dynamo):
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

# Test successfull logout with valid inputs
def test_logout(client, mock_cognito, user_data_1, clear_dynamo):
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


# Test for error upon logout with missing input fields
def test_logout_bad_input(client, mock_cognito, user_data_1, clear_dynamo):
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
        headers={'Authorization': 'invalid_token'},
        content_type='application/json'
    )
    assert response.status_code == 400
    assert response.json.get('message') == 'Access token is invalid.'


# Test for error upon logging out with invalid token
def test_logout_invalid_token(client, mock_cognito, clear_dynamo):
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

# Test successfull user deletion with valid input
def test_delete_user(client, mock_cognito, user_data_1, clear_dynamo):
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
    mock_cognito,
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
def test_delete_non_existing_user(client, mock_cognito, clear_dynamo):
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
    mock_cognito,
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
    mock_cognito,
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
