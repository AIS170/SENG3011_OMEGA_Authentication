import json


def test_signup(client, mock_cognito):
    data = {
        'username': 'jd101',
        'email': 'john.doe@example.com',
        'password': 'goodPassword123!',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup', data=json.dumps(data),
        content_type='application/json'
    )

    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': 'jd101'}),
        content_type='application/json'
    )
    assert response.status_code == 200


def test_login(client, mock_cognito):
    data = {
        'username': 'jd101',
        'email': 'john.doe@example.com',
        'password': 'goodPassword123!',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup',
        data=json.dumps(data),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': 'jd101'}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps({'username': 'jd101', 'password': 'goodPassword123!'}),
        content_type='application/json'
    )
    assert response.status_code == 200


def test_logout(client, mock_cognito):
    data = {
        'username': 'jd101',
        'email': 'john.doe@example.com',
        'password': 'goodPassword123!',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup', data=json.dumps(data),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': 'jd101'}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps({'username': 'jd101', 'password': 'goodPassword123!'}),
        content_type='application/json'
    )
    token = response.get_json().get('access_token')
    assert response.status_code == 200

    response = client.post(
        '/logout',
        data=json.dumps({'AccessToken': token}),
        content_type='application/json'
    )
    assert response.status_code == 200


def test_username_in_use(client, mock_cognito):
    data1 = {
        'username': 'jd101',
        'email': 'john.doe@example.com',
        'password': 'goodPassword123!',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup',
        data=json.dumps(data1),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': 'jd101'}),
        content_type='application/json'
    )
    assert response.status_code == 200

    data2 = {
        'username': 'jd101',
        'email': 'jane.doe@example.com',
        'password': 'goodPassword123!',
        'name': 'Jane Doe'
    }

    response = client.post(
        '/signup',
        data=json.dumps(data2),
        content_type='application/json'
    )
    assert response.status_code == 400
    assert response.json.get('message') == 'The username is already in use.'


def test_bad_password(client, mock_cognito):
    data = {
        'username': 'jd101',
        'email': 'john.doe@example.com',
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


def test_user_not_exist(client, mock_cognito):
    response = client.post(
        '/login',
        data=json.dumps({'username': 'jd101', 'password': 'goodPassword123!'}),
        content_type='application/json'
    )
    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


def test_incorrect_password(client, mock_cognito):
    data = {
        'username': 'jd101',
        'email': 'john.doe@example.com',
        'password': 'goodPassword123!',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup',
        data=json.dumps(data),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': 'jd101'}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps({'username': 'jd101', 'password': 'goodPassword456!'}),
        content_type='application/json'
    )
    assert response.status_code == 401
    assert response.json.get('message') == (
        'You are not authorised to complete this action.'
    )


def test_user_not_confirmed(client, mock_cognito):
    data = {
        'username': 'jd101',
        'email': 'john.doe@example.com',
        'password': 'goodPassword123!',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup',
        data=json.dumps(data),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps({'username': 'jd101', 'password': 'goodPassword123!'}),
        content_type='application/json'
    )
    assert response.status_code == 403
    assert response.json.get('message') == 'User is not confirmed'


def test_logout_invalid_token(client, mock_cognito):
    response = client.post(
        '/logout',
        data=json.dumps({'AccessToken': '123'}),
        content_type='application/json'
    )
    assert response.status_code == 401
    assert response.json.get('message') == (
        'You are not authorised to complete this action.'
    )


def test_delete_user(client, mock_cognito):
    data = {
        'username': 'jd101',
        'email': 'john.doe@example.com',
        'password': 'goodPassword123!',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup',
        data=json.dumps(data),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': 'jd101'}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.delete(
        '/delete_user',
        data=json.dumps({'username': 'jd101', 'password': 'goodPassword123!'}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/login',
        data=json.dumps({'username': 'jd101', 'password': 'goodPassword123!'}),
        content_type='application/json'
    )
    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


def test_delete_non_existing_user(client, mock_cognito):
    response = client.delete(
        '/delete_user',
        data=json.dumps({'username': 'jd101', 'password': 'goodPassword123!'}),
        content_type='application/json'
    )
    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


def test_delete_user_incorrect_password(client, mock_cognito):
    data = {
        'username': 'jd101',
        'email': 'john.doe@example.com',
        'password': 'goodPassword123!',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup',
        data=json.dumps(data),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': 'jd101'}),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.delete(
        '/delete_user',
        data=json.dumps(
            {
                'username': 'jd101',
                'password': 'incorrectPassword123!'
            }
        ),
        content_type='application/json'
    )
    assert response.status_code == 401
    assert response.json.get('message') == (
        'You are not authorised to complete this action.'
    )


def test_admin_confirm_signup_not_allowed(client, mock_cognito, monkeypatch):
    monkeypatch.setenv('TESTING', 'false')

    data = {
        'username': 'jd101',
        'email': 'john.doe@example.com',
        'password': 'goodPassword123!',
        'name': 'John Doe'
    }

    response = client.post(
        '/signup',
        data=json.dumps(data),
        content_type='application/json'
    )
    assert response.status_code == 200

    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': 'jd101'}),
        content_type='application/json'
    )
    assert response.status_code == 403
    assert response.json.get('message') == (
        'You are not authorised to perform this action.'
    )


def test_admin_confirm_signup_user_not_found(client, mock_cognito):
    response = client.post(
        '/admin/confirm_signup',
        data=json.dumps({'username': 'jd101'}),
        content_type='application/json'
    )
    assert response.status_code == 404
    assert response.json.get('message') == 'The user could not be found.'


def test_confirm_signup(client, mock_cognito, monkeypatch):
    def mock_confirmation(**kwargs):
        return {}
    monkeypatch.setattr(mock_cognito, 'confirm_sign_up', mock_confirmation)

    response = client.post(
        '/confirm_signup', json={'username': 'jd101', 'conf_code': '123456'}
    )
    assert response.status_code == 200
