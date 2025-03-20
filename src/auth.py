import boto3
from config import REGION, CLIENT_ID, CLIENT_SECRET
import base64
import hmac
import hashlib

client = boto3.client("cognito-idp", region_name=REGION)
db = boto3.resource("dynamodb", region_name=REGION)
table = db.Table("authentication")


def sign_up(username, email, password, name):
    try:
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

        table.put_item(
            Item={
                "userID": ret["UserSub"],
                "username": username,
                "email": email,
                "name": name,
                "status": "UNCONFIRMED",
            }
        )

        return {
            "message": (
                "User registered successfully. Please check email "
                "for confirmation code"
            ),
            "user_sub": ret["UserSub"]
        }
    except Exception as error:
        return {"error": str(error)}


def confirm_signup(username, conf_code):
    try:
        secret_hash = generate_secret_hash(username, CLIENT_ID, CLIENT_SECRET)

        client.confirm_sign_up(
            ClientId=CLIENT_ID,
            Username=username,
            ConfirmationCode=conf_code,
            SecretHash=secret_hash
        )

        userSub = get_user_sub(username)

        table.update_item(
            Key={"userID": userSub},
            UpdateExpression="SET #status = :status",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={":status": "CONFIRMED"}
        )

        return {"message": "Confirmation successfull"}
    except Exception as error:
        return {"error": str(error)}


def get_user_sub(username):
    try:
        response = table.scan(
            FilterExpression="username = :username",
            ExpressionAttributeValues={":username": username}
        )
        if 'Items' in response and len(response['Items']) > 0:
            return response['Items'][0].get('userID')
        else:
            raise Exception("User not found")

    except Exception as e:
        raise Exception(f"error: {str(e)}")


def generate_secret_hash(username, client_id, client_secret):
    message = bytes(username + client_id, 'utf-8')
    clientSecret = bytes(client_secret, 'utf-8')
    dig = hmac.new(clientSecret, message, hashlib.sha256)

    return base64.b64encode(dig.digest()).decode()


def login(username, password):
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
    except Exception as error:
        return {"error": str(error)}


# logout
def logout(access_token):
    try:
        client.global_sign_out(AccessToken=access_token)
        return {"message": "Logout Successful!"}
    except Exception as error:
        return {"error": str(error)}
