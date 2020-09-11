from flask import Blueprint, request

from app.core.aop.authority import authentication, authorization
from app.core.model.request_model import RequestModel
from app.core.model.respond_model import RespondModel
from app.core.service import user_service
from app.core.service.user_service import generate_token, update_password, get_all_user_info, get_password_from_db
from app.tools.jwt_tools import generate_jwt, decode_jwt

api = Blueprint('user_api', __name__)


@api.route('/login', methods=['post'])
def login():
    """
        user login
    :return: respond model with jwt token in headers
    """
    request_model = RequestModel(request)
    user_info_db = user_service.login(request_model.data.get('user_info'))
    respond_model = RespondModel()
    if user_info_db is not None:
        respond_model.token = generate_jwt(user_info_db)
        respond_model.message = 'login success'
        respond_model.code = 20000
    else:
        respond_model.message = 'username or password wrong!'
    return respond_model.dump_json()


@api.route('/user', methods=['post'])
@authentication
def user():
    """
        update user info
    :return: respond model
    """
    request_model = RequestModel(request)
    user_info_form = request_model.data.get('user_info')
    jwt = request_model.token
    user_info_jwt = decode_jwt(jwt)['user_info']
    respond_model = RespondModel()
    save_user_info = False
    if (user_info_form and user_info_form['name'] == user_info_jwt['name']) or 'admin' in user_info_jwt['roles']:
        if not user_info_form.get('password') or user_info_form.get('password') == '':
            user_info_form['password'] = get_password_from_db(user_info_form)
            save_user_info = user_service.update(user_info_form)
        else:
            save_user_info = update_password(user_info_form)
        respond_model.message = 'success'
        if save_user_info:
            respond_model.token = generate_jwt(user_info_form)
        return respond_model
    respond_model.message = 'error'
    return respond_model


@api.route('/user/info', methods=['get'])
@authentication
def user_info():
    """
        get user info
    :return: respond model
    """
    request_model = RequestModel(request)
    jwt = request_model.token
    user_info_jwt = decode_jwt(jwt)['user_info']
    respond_model = RespondModel()
    respond_model.message = 'success'
    respond_model.data = user_info_jwt
    return respond_model


@api.route('/user/logout', methods=['get'])
def user_logout():
    """
        logout
    :return: respond model
    """
    respond_model = RespondModel()
    respond_model.message = 'success'
    respond_model.token = ''
    respond_model.code = 20000
    return respond_model.dump_json(), 200


@api.route('/user/token', methods=['post'])
@authentication
def save_token():
    """
        save plugin token
    :return:
    """
    request_model = RequestModel(request)
    jwt = request_model.token
    user_info_jwt = decode_jwt(jwt)['user_info']
    respond_model = RespondModel()
    respond_model.message = 'success'
    token = generate_token(user_info_jwt)
    respond_model.data['token'] = token
    user_info_jwt['token'] = token
    respond_model.token = generate_jwt(user_info_jwt)
    return respond_model


@api.route('/setting/user/all', methods=['get'])
@authorization('admin')
def install_by_version():
    """
        get all user info
    :return:
    """
    respond_model = RespondModel()
    respond_model.data = get_all_user_info()
    return respond_model
