import json
import os
import boto3
import requests
from config import CLIENT_ID, CLIENT_SECRET, DB, POOL_ID, COGNITO_ROLE_ARN, DYNAMO_ROLE_ARN
from constants import REGION
import base64
import hmac
import hashlib
from botocore.exceptions import ClientError
from email_validator import validate_email, EmailNotValidError


def get_cognito():
    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn=COGNITO_ROLE_ARN,
        RoleSessionName="CognitoRoleSession"
    )

    credentials = assumed_role_object['Credentials']

    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=REGION
    )

    cognito = session.client('cognito-idp', region_name=REGION)
    return cognito


def get_dynamo():
    sts_client = boto3.client('sts')
    assumed_role_object = sts_client.assume_role(
        RoleArn=DYNAMO_ROLE_ARN,
        RoleSessionName="AssumeRoleSession1"
    )

    credentials = assumed_role_object['Credentials']
    aws_access_key_id = credentials['AccessKeyId']
    aws_secret_access_key = credentials['SecretAccessKey']

    session = boto3.Session(
        aws_session_token=credentials['SessionToken'],
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=REGION,
    )

    db = session.resource("dynamodb", region_name=REGION)
    table = db.Table(DB)
    table.load()

    return table


def put_item_to_DB(item: dict):
    table = get_dynamo()

    response = table.put_item(Item=item)
    return response


def get_item_from_DB(username):
    table = get_dynamo()

    response = table.scan(
        FilterExpression="username = :username",
        ExpressionAttributeValues={":username": username}
    )
    if 'Items' in response and len(response['Items']) > 0:
        return response['Items'][0]
    else:
        return None


def update_item_status(username, status):
    table = get_dynamo()

    response = table.update_item(
        Key={"userID": get_user_sub(username)},
        UpdateExpression="SET #status = :status",
        ExpressionAttributeNames={"#status": "status"},
        ExpressionAttributeValues={":status": status}
    )

    return response


def delete_item_from_DB(username):
    table = get_dynamo()

    response = table.delete_item(
        Key={'userID': get_user_sub(username)}
    )

    return response


def get_error_message(error):
    error_messages = {
            "UsernameExistsException": "The username is already in use.",
            "InvalidPasswordException": "Invalid password provided.",
            "UserNotFoundException": "The user could not be found.",
            "NotAuthorizedException": (
                "You are not authorised to complete this action."
            ),
            "UserNotConfirmedException": "User is not confirmed",
            "ExpiredCodeException": (
                "The provided confirmation code is incorrect."
            ),
            "CodeMismatchException": (
                "The provided confirmation code is incorrect."
            )
        }

    if isinstance(error, ClientError):
        return (
            error.response['Error']['Code'],
            error_messages.get(
                error.response['Error']['Code'],
                "An unexpected error has occurred"
            )
        )
    else:
        return "UnknownError", "An unexpected error has occurred"


def sign_up(username, email, password, name):
    client = get_cognito()

    if not all([username, email, password, name]):
        return {
            "error_code": "BadInput",
            "message": (
                "All fields must be provided (username, email, password, name)"
            )
        }

    if not CLIENT_ID or not CLIENT_SECRET:
        return {
            "error_code": "MissingSecrets",
            "message": "CLIENT_ID or CLIENT_SECRET is not set"
        }

    try:
        validate_email(email)

        secret_hash = generate_secret_hash(username, CLIENT_ID, CLIENT_SECRET)

        ret = client.sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            Password=password,
            UserAttributes=[
                {"Name": "email", "Value": email},
                {"Name": "name", "Value": name},
                {"Name": "preferred_username", "Value": username}
            ],
            SecretHash=secret_hash
        )
        item = {
            "userID": ret["UserSub"],
            "username": username,
            "email": email,
            "name": name,
            "status": "UNCONFIRMED"
        }
        put_item_to_DB(item)

        return {
            "message": (
                "User registered successfully. Please check email "
                "for confirmation code"
            ),
            "user_sub": ret["UserSub"]
        }
    except EmailNotValidError:
        return {
            "error_code": "InvalidEmail",
            "message": "The provided email is in an invalid format"
        }
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message + str(error)
        }


def confirm_signup(username, conf_code):
    client = get_cognito()

    if not all([username, conf_code]):
        return {
            "error_code": "BadInput",
            "message": "All fields must be provided (username, conf_code)"
        }

    try:
        user_details = client.admin_get_user(
            UserPoolId=POOL_ID,
            Username=username
        )

        status = user_details.get('UserStatus')

        if status == 'CONFIRMED':
            return {
                "error_code": "NoVerificationRequired",
                "message": "User has already confirmed their email."
            }

        secret_hash = generate_secret_hash(username, CLIENT_ID, CLIENT_SECRET)

        client.confirm_sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            ConfirmationCode=conf_code,
            SecretHash=secret_hash
        )

        update_item_status(username, "CONFIRMED")

        url = (
            "http://retrieval-load-balancer-334368182.ap-southeast-2.elb"
            ".amazonaws.com/v1/register/"
        )

        requests.post(
            url,
            data=json.dumps({'username': username}),
            headers={'Content-Type': 'application/json'}
        )

        return {"message": "Confirmation successful"}
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }


def admin_confirm_signup(username):
    client = get_cognito()

    if not username:
        return {
            "error_code": "BadInput",
            "message": "All fields must be provided (username)"
        }

    if os.getenv('TESTING') == 'false':
        return {
            "error_code": "MethodNotAllowed",
            "message": "You are not authorised to perform this action."
        }

    try:
        user_details = client.admin_get_user(
            UserPoolId=POOL_ID,
            Username=username
        )

        status = user_details.get('UserStatus')

        if status == 'CONFIRMED':
            return {
                "error_code": "NoVerificationRequired",
                "message": "User has already confirmed their email."
            }

        client.admin_confirm_sign_up(
            UserPoolId=POOL_ID,
            Username=username
        )

        client.admin_update_user_attributes(
            UserPoolId=POOL_ID,
            Username=username,
            UserAttributes=[
                {
                    'Name': 'email_verified',
                    'Value': 'true'
                }
            ]
        )

        update_item_status(username, "CONFIRMED")

        return {"message": "Confirmation successful"}
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }


def login(username, password):
    client = get_cognito()

    if not all([username, password]):
        return {
            "error_code": "BadInput",
            "message": "All fields must be provided (username, password)"
        }

    try:
        secret_hash = generate_secret_hash(username, CLIENT_ID, CLIENT_SECRET)
        response = client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
        )

        id_token = response["AuthenticationResult"]["IdToken"]
        access_token = response["AuthenticationResult"]["AccessToken"]
        refresh_token = response["AuthenticationResult"]["RefreshToken"]

        return {
            "message": "Login Successful",
            "id_token": id_token,
            "access_token": access_token,
            "refresh_token": refresh_token
        }
    except client.exceptions.NotAuthorizedException:
        return {
            "error_code": "InvalidCredentials",
            "message": "The username or password is incorrect."
        }
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }


# logout
def logout(access_token):
    client = get_cognito()

    try:
        client.get_user(AccessToken=access_token)

        client.global_sign_out(AccessToken=access_token)
        return {"message": "Logout Successful!"}
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }


def delete_user(username, password):
    client = get_cognito()

    if not all([username, password]):
        return {
            "error_code": "BadInput",
            "message": "All fields must be provided (username, password)"
        }

    try:
        secret_hash = generate_secret_hash(username, CLIENT_ID, CLIENT_SECRET)
        client.initiate_auth(
            ClientId=CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
                'SECRET_HASH': secret_hash
            }
        )

        client.admin_delete_user(
            UserPoolId=POOL_ID,
            Username=username
        )

        delete_item_from_DB(username)

        return {"message": f"User {username} deleted successfully"}
    except client.exceptions.NotAuthorizedException:
        return {
            "error_code": "InvalidCredentials",
            "message": "The password is incorrect."
        }
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }


def forgot_password(username):
    if not username:
        return {
            "error_code": "BadInput",
            "message": "All fields must be provided (username)"
        }

    client = get_cognito()

    try:
        secret_hash = generate_secret_hash(username, CLIENT_ID, CLIENT_SECRET)
        client.forgot_password(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=username
        )

        return {
            "message": (
                "A confirmation code has been sent to your email to reset your"
                " password"
            )
        }
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }


def confirm_forgot_password(username, conf_code, new_password):
    if not all([username, conf_code, new_password]):
        return {
            "error_code": "BadInput",
            "message": (
                "All fields must be provided (username, conf_code, "
                "new_password)"
            )
        }

    client = get_cognito()

    try:
        secret_hash = generate_secret_hash(username, CLIENT_ID, CLIENT_SECRET)
        client.confirm_forgot_password(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=username,
            ConfirmationCode=conf_code,
            Password=new_password
        )

        return {"message": "Password has been reset successfully"}
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }


def resend_confirmation_code(username):
    if not username:
        return {
            "error_code": "BadInput",
            "message": "All fields must be provided (username)"
        }

    try:
        client = get_cognito()

        user_details = client.admin_get_user(
            UserPoolId=POOL_ID,
            Username=username
        )

        status = user_details.get('UserStatus')

        if status == 'CONFIRMED':
            return {
                "error_code": "NoVerificationRequired",
                "message": "User has already confirmed their email."
            }

        secret_hash = generate_secret_hash(username, CLIENT_ID, CLIENT_SECRET)
        client.resend_confirmation_code(
            ClientId=CLIENT_ID,
            SecretHash=secret_hash,
            Username=username
        )

        return {
            "message": "A new confirmation code has been sent to your email"
        }
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }


def update_email(access_token, new_email):
    if not new_email:
        return {
            "error_code": "BadInput",
            "message": "All fields must be provided (new_email)"
        }

    try:
        client = get_cognito()
        username = client.get_user(AccessToken=access_token)['Username']

        validate_email(new_email)

        client.update_user_attributes(
            AccessToken=access_token,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': new_email
                }
            ]
        )

        client.admin_update_user_attributes(
            UserPoolId=POOL_ID,
            Username=username,
            UserAttributes=[
                {
                    'Name': 'email_verified',
                    'Value': 'true'
                }
            ]
        )

        return {"message": "Email successfully updated."}
    except EmailNotValidError:
        return {
            "error_code": "InvalidEmail",
            "message": "The provided email is in an invalid format"
        }
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }


def update_password(access_token, old_password, new_password):
    if not all([old_password, new_password]):
        return {
            "error_code": "BadInput",
            "message": (
                "All fields must be provided (old_password, new_password)"
            )
        }

    try:
        client = get_cognito()
        username = client.get_user(AccessToken=access_token)['Username']
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }

    try:
        client = get_cognito()
        username = client.get_user(AccessToken=access_token)['Username']

        client.change_password(
            PreviousPassword=old_password,
            ProposedPassword=new_password,
            AccessToken=access_token
        )

        client.admin_update_user_attributes(
            UserPoolId=POOL_ID,
            Username=username,
            UserAttributes=[
                {
                    'Name': 'email_verified',
                    'Value': 'true'
                }
            ]
        )

        return {"message": "Password successfully updated."}
    except client.exceptions.InvalidPasswordException:
        return {
            "error_code": "InvalidPasswordException",
            "message": "The new password is of invalid format"
        }
    except client.exceptions.NotAuthorizedException:
        return {
            "error_code": "InvalidPasswordException",
            "message": (
                "The provided current password does not match the true "
                "current password"
            )
        }
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }


def user_info(access_token):
    try:
        client = get_cognito()
        user_info = client.get_user(AccessToken=access_token)

        properties = {}
        for attribute in user_info["UserAttributes"]:
            properties[attribute["Name"]] = attribute["Value"]

        return {
            "message": "User info retrieved successfully",
            "name": properties.get("name"),
            "username": user_info['Username'],
            "email": properties.get("email")
        }
    except Exception as error:
        code, message = get_error_message(error)
        return {
            "error_code": code,
            "message": message
        }


def get_user_sub(username):
    response = get_item_from_DB(username)

    if response:
        return response.get('userID')
    else:
        return None


def generate_secret_hash(username, client_id, client_secret):
    message = bytes(username + client_id, 'utf-8')
    clientSecret = bytes(client_secret, 'utf-8')
    dig = hmac.new(clientSecret, message, hashlib.sha256)

    return base64.b64encode(dig.digest()).decode()
