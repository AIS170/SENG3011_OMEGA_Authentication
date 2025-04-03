from flask import Blueprint, request, jsonify
import sys

if "src" in sys.modules:
    from src import auth
else:
    import auth

routes = Blueprint("routes", __name__)
CLIENT_ROLE_ARN = "arn:aws:iam::149536468960:role/shareDynamoDB"
CLIENT_DYNAMO_NAME = "authentication"

ERROR_CODE_DICT = {
    "UsernameExistsException": 400,
    "InvalidPasswordException": 400,
    "UserNotFoundException": 404,
    "UserNotConfirmedException": 403,
    "NotAuthorizedException": 401,
    "CodeMismatchException": 400,
    "ExpiredCodeException": 400,
    "MethodNotAllowed": 403,
    "UnknownError": 500
}


# @routes.route('/test', methods=['POST'])
# def test():
#     sts_client = boto3.client('sts')

#     # Step 1: Assume the role
#     assumed_role_object = sts_client.assume_role(
#         RoleArn='arn:aws:iam::149536468960:role/shareDynamoDB',
#         RoleSessionName='AssumeRoleSession1'
#     )

#     credentials = assumed_role_object['Credentials']

#     # Step 2: Create a session with the assumed role credentials
#     assumed_session = boto3.Session(
#         aws_access_key_id=credentials['AccessKeyId'],
#         aws_secret_access_key=credentials['SecretAccessKey'],
#         aws_session_token=credentials['SessionToken'],
#         region_name=REGION
#     )

#     # Step 3: Create a DynamoDB **resource** (not client)
#     dynamodb = assumed_session.resource('dynamodb')

#     # Step 4: Get the table resource
#     table = dynamodb.Table('authentication')

#     # Step 5: Put the item into the table
#     response = table.put_item(
#         Item={
#             "userID": "wowowoow11",
#             "email": "test101@gmail.com",
#             "name": "Test User",
#             "status": "UNCONFIRMED",
#             "username": "test02"
#         }
#     )

#     print(response)
#     return jsonify(response), 200


@routes.route('/signup', methods=['POST'])
def sign_up():
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    name = request.json.get('name')

    ret = auth.sign_up(username, email, password, name)
    if 'error_code' in ret:
        error_code = ret['error_code']
        status = ERROR_CODE_DICT.get(error_code, 500)
        return jsonify(ret), status
    else:
        return jsonify(ret), 200


@routes.route('/confirm_signup', methods=['POST'])
def confirm_signup():
    username = request.json.get('username')
    conf_code = request.json.get('conf_code')

    ret = auth.confirm_signup(username, conf_code)
    if 'error_code' in ret:
        error_code = ret['error_code']
        status = ERROR_CODE_DICT.get(error_code, 500)
        return jsonify(ret), status
    else:
        return jsonify(ret), 200


@routes.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    ret = auth.login(username, password)
    if 'error_code' in ret:
        error_code = ret['error_code']
        status = ERROR_CODE_DICT.get(error_code, 500)
        return jsonify(ret), status
    else:
        return jsonify(ret), 200


@routes.route('/logout', methods=['POST'])
def logout():
    access_token = request.json.get('AccessToken')
    ret = auth.logout(access_token)
    if 'error_code' in ret:
        error_code = ret['error_code']
        status = ERROR_CODE_DICT.get(error_code, 500)
        return jsonify(ret), status
    else:
        return jsonify(ret), 200


@routes.route("/delete_user", methods=["DELETE"])
def delete_user_route():
    username = request.json.get('username')
    password = request.json.get('password')

    ret = auth.delete_user(username, password)
    if 'error_code' in ret:
        error_code = ret['error_code']
        status = ERROR_CODE_DICT.get(error_code, 500)
        return jsonify(ret), status
    else:
        return jsonify(ret), 200


@routes.route("/admin/confirm_signup", methods=["POST"])
def admin_confirm_signup():
    username = request.json.get('username')

    ret = auth.admin_confirm_signup(username)
    if 'error_code' in ret:
        error_code = ret['error_code']
        status = ERROR_CODE_DICT.get(error_code, 500)
        return jsonify(ret), status
    else:
        return jsonify(ret), 200


def register_routes(app):
    app.register_blueprint(routes)
