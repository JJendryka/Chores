from flask import Blueprint, request, render_template, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
from authlib.integrations.flask_oauth2 import AuthorizationServer
from models import db, User, Client, Token, AuthorizationCode
from werkzeug.security import gen_salt
from authlib.integrations.sqla_oauth2 import (
    create_query_client_func,
    create_save_token_func
)
from authlib.oauth2.rfc6749 import grants
import time
from authlib.integrations.flask_oauth2 import ResourceProtector, current_token
from authlib.oauth2.rfc6750 import BearerTokenValidator

server = AuthorizationServer()
blueprint = Blueprint('auth', __name__)

## TODO: Change local session management (session id instead of username)

################################################################################
# User - A person that is using this service
# Client - An app that connects to this service and asks for user data
################################################################################


# OAuth Grant type that involves user giving it's credentials to a client and client loging in on their's behalf
class PasswordGrant(grants.ResourceOwnerPasswordCredentialsGrant):
    def authenticate_user(self, username, password):
        user = User.query.filter_by(username=username).first()
        if user.check_password(password):
            return user

# OAuth grant type used by apps that can store a secret securely
class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = [
        'client_secret_basic',
        'client_secret_post',
        'none',
    ]

    def save_authorization_code(self, code, request):
        client = request.client
        auth_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            redirect_uri=request.redirect_uri,
            scope=request.scope,
            user_id=request.user.id,
        )
        db.session.add(auth_code)
        db.session.commit()
        return auth_code

    def query_authorization_code(self, code, client):
        item = AuthorizationCode.query.filter_by(
            code=code, client_id=client.client_id).first()
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):
        db.session.delete(authorization_code)
        db.session.commit()

    def authenticate_user(self, authorization_code):
        return User.query.get(authorization_code.user_id)

def init_app(app, db):
    query_client = create_query_client_func(db.session, Client)
    save_token = create_save_token_func(db.session, Token)
    server.init_app(app, query_client=query_client, save_token=save_token)

    import logging
    import sys
    log = logging.getLogger('authlib')
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.setLevel(logging.DEBUG)

    # Register grants
    server.register_grant(grants.ImplicitGrant)
    server.register_grant(PasswordGrant)
    server.register_grant(AuthorizationCodeGrant)

class LoginForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired()]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired()]
    )
    submit = SubmitField('Log in')

class AuthorizationForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired()]
    )
    password = PasswordField(
        'Password',
        validators=[DataRequired()]
    )
    submit = SubmitField('Authorize')

class RegisterForm(FlaskForm):
    username = StringField(
        'Username',
        validators=[DataRequired(), Length(min=2), Length(max=64)]
    )
    password = PasswordField(
        'Password',
        validators=[
            Length(min=8, message='The password needs to be at least 8 characters long'),
            DataRequired()
        ]
    )
    confirm = PasswordField(
        'Confirm password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords do not match')
        ]
    )
    is_admin = BooleanField(
        "Is admin"
    )
    submit = SubmitField('Register')

class ChangePasswordForm(FlaskForm):
    password = PasswordField(
        'New password',
        validators=[
            Length(min=8, message='The password needs to be at least 8 characters long'),
            DataRequired()
        ]
    )
    confirm = PasswordField(
        'Confirm password',
        validators=[
            DataRequired(),
            EqualTo('password', message='Passwords do not match')
        ]
    )
    submit = SubmitField('Change password')

class RegisterClientForm(FlaskForm):
    client_name = StringField(
        'Client Name',
        validators=[DataRequired()]
    )
    client_uri = StringField(
        "Client URI"
    )
    redirect_uris = TextAreaField(
        "Redirect URIs",
        validators=[DataRequired()]
    )
    response_types = TextAreaField(
        "Response Types",
        validators=[DataRequired()]
    )
    token_endpoint_auth_method = SelectField(
        "Token Endpoint Authentication Method",
        choices=[("none", "None"), ("client_secret_basic", "Client Secret Basic"), ("client_secret_post", "Client Secret Post")],
        validators=[DataRequired()]
    )
    submit = SubmitField('Register client')

@blueprint.route('/auth/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user is not None and user.is_admin:
            form = RegisterForm()
            if form.validate_on_submit():
                if User.query.filter_by(username=form.username.data).scalar() is None:
                    user = User(username=form.username.data)
                    user.set_password(form.password.data)
                    user.is_admin = form.is_admin.data
                    db.session.add(user)
                    db.session.commit()
                    return render_template('success.html')
                else:
                    form.username.errors.append('Username already taken.')
            return render_template('register.html', form=form)
        else:
            return "User does not have admin privileges", 403
    else:
        return "Need to be logged in", 403

@blueprint.route('/auth/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user is not None:
            form = ChangePasswordForm()
            if form.validate_on_submit():
                user.set_password(form.password.data)
                db.session.commit()
                return render_template('success.html')
            return render_template('change_password.html', form=form)
        else:
            return "User does not exist."
    else:
        return "Needs to be logged in."

@blueprint.route('/auth/login', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return "Already logged in."

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.check_password(form.password.data):
            session['username'] = form.username.data
            return "Log in successfull."
        else:
            form.password.errors.append('Invalid username or password.')

    return render_template('login.html', form=form)

@blueprint.route('/auth/logout', methods=['GET', 'POST'])
def logout():
    if 'username' in session:
        session.pop('username', None)
        return "User logged out."
    else:
        return "User already logged out."

@blueprint.route('/auth/authorize', methods=['GET', 'POST'])
def authorize():
    form = AuthorizationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is not None and user.check_password(form.password.data):
            return server.create_authorization_response(request=request, grant_user=user)
        else:
            form.password.errors.append('Invalid username or password.')
    return render_template('authorize.html', form=form)

def split_by_crlf(s):
    return [v for v in s.splitlines() if v]

@blueprint.route('/auth/register_client', methods=['GET', 'POST'])
def register_client():
    if 'username' in session:
        username = session['username']
        user = User.query.filter_by(username=username).first()
        if user is not None and user.is_admin:
            form = RegisterClientForm()
            if form.validate_on_submit():
                client = Client()
                client.user_id = user.id
                client.client_id = gen_salt(24)
                client.client_id_issued_at = int(time.time())
                client_metadata = {
                    "client_name": form.client_name.data,
                    "client_uri": form.client_uri.data,
                    "redirect_uris": split_by_crlf(form.redirect_uris.data),
                    "token_endpoint_auth_method": form.token_endpoint_auth_method.data,
                    "response_types": split_by_crlf(form.response_types.data),
                }
                client.set_client_metadata(client_metadata)

                if form.token_endpoint_auth_method.data == "none":
                    client.client_secret = ''
                else:
                    client.client_secret = gen_salt(48)

                db.session.add(client)
                db.session.commit()
                return render_template('client_register_success.html', client_id=client.client_id, client_secret=client.client_secret)
            return render_template('register_client.html', form=form)
        else:
            return "User does not have admin privileges", 403
    else:
        return "Need to be logged in", 403


@blueprint.route('/auth/token', methods=['POST'])
def issue_token():
    return server.create_token_response()


require_oauth = ResourceProtector()
from authlib.integrations.sqla_oauth2 import create_bearer_token_validator
BearerTokenValidator = create_bearer_token_validator(db.session, Token)
require_oauth.register_token_validator(BearerTokenValidator())