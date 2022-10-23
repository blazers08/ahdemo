"""auth module"""
import functools
import re

from flask import request, session, render_template, \
  make_response, redirect, url_for, flash, Blueprint, g
from werkzeug.security import check_password_hash, generate_password_hash
from authlib.integrations.flask_client import OAuth
from apps.models import Users, db, ma
from sqlalchemy import exc
from datetime import datetime
from flask_restful import Resource
from marshmallow import fields
from flask_apispec.views import MethodResource
from flask_apispec import doc, use_kwargs, marshal_with


core_bp = Blueprint('core', __name__, url_prefix='/')
api_bp = Blueprint('api', __name__)
oauth = OAuth()


class UserSchema(ma.SQLAlchemyAutoSchema):
  class Meta:
    model = Users
    # fields = ['email', 'password']
    sqla_session = db.session


@core_bp.route('/')
def home():
  """default home page"""
  return render_template('dashboard/index.html')


class AuthRegister(MethodResource, Resource):
  """Register class"""
  @doc(description='Register function', tags=['Auth'])
  @use_kwargs({'email': fields.Str(required=True), 'password': fields.Str(required=True)}, \
    location=('form'))
  @marshal_with(UserSchema)
  def post(self, **_kwargs):
    """register get method"""
    email, password = (
        request.form['email'],
        request.form['password']
    )
    print(email, password)
    error = None

    # check password criteria
    lowercase_error = re.search(r'[a-z]', password) is None
    if lowercase_error:
      error = 'User password should contains at least one lowercase character.'
      flash(error)

    uppercase_error = re.search(r'[A-Z]', password) is None
    if uppercase_error:
      error = 'User password should contains at least one uppercase character.'
      flash(error)

    digit_error = re.search(r'\d', password) is None
    if digit_error:
      error = 'User password should contains at least one digit character.'
      flash(error)

    symbol_error = re.search(r'\W', password) is None
    if symbol_error:
      error = 'User password should contains at least one special character.'
      flash(error)

    length_error = len(password) < 8
    if length_error:
      error = 'User password should at least 8 characters.'
      flash(error)

    if error is None:
      try:
        new_user = Users(email=email, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
      except exc.IntegrityError:
        error = f'User {email} is already registered.'
      else:
        return redirect(url_for('authsign'))
      flash(error)

    return make_response(render_template('auth/register.html'))


  @doc(description='Get Register page', tags=['Auth'])
  def get(self):
    """register get method"""
    headers = {'Content-Type': 'text/html'}
    return make_response(render_template('auth/register.html'), 200, headers)


class AuthSign(MethodResource, Resource):
  """Sign in class"""
  @doc(description='Sign in function', tags=['Auth'])
  @use_kwargs({'email': fields.Str(required=True), 'password': fields.Str(required=True)}, \
    location=('form'))
  @marshal_with(UserSchema)
  def post(self, **_kwargs):
    """signin post method"""
    email, password = (
        request.form['email'],
        request.form['password']
    )
    error = None

    user = Users.query.filter_by(email=email).first()
    print('login user', user)

    if user:
      if user.email is None:
        error = 'Incorrect email.'
      elif not check_password_hash(user.password, password):
        error = 'Incorrect password.'

      if error is None:
        session.clear()
        session['user_id'] = user.id
        user.logged_in_times += 1
        print('time', datetime.now())
        session['last_session_time'] = datetime.now()
        db.session.commit()
        return redirect(url_for('core.home'))
    else:
      error = 'Account does not exist.'

    flash(error)

    return make_response(render_template('auth/login.html'))


  @doc(description='Get sign in page', tags=['Auth'])
  def get(self):
    """signin get method"""
    headers = {'Content-Type': 'text/html'}
    return make_response(render_template('auth/login.html'), 200, headers)


class AuthGoogle(MethodResource, Resource):
  """Google Auth class"""
  @doc(description='Google auth setting and sign in function', tags=['Auth_Google'])
  def get(self):
    """google auth setting"""
    google_cleint_id = '107151843773-ett7411orh515mpuclu4rn15vjttjmhc.apps.googleusercontent.com'
    google_client_secret = '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'

    conf_url = 'https://accounts.google.com/.well-known/openid-configuration'
    oauth.register(
      name='google',
      client_id=google_cleint_id,
      client_secret=google_client_secret,
      server_metadata_url=conf_url,
      client_kwargs={
        'scope': 'openid email profile'
      }
    )

    # Redirect to google_auth function
    redirect_uri = url_for('authgooglelogin', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


class AuthGoogleLogin(MethodResource, Resource):
  """Get Google User Info"""
  @doc(description='Google authentication', tags=['Auth_Google'])
  def get(self):
    """redirect and get token user info"""
    token = oauth.google.authorize_access_token()
    userinfo = token['userinfo']
    error = None
    session['email'] = userinfo['email']

    user = Users.query.filter_by(email=userinfo['email']).first()

    if user is None:
      new_user = Users(email=userinfo['email'], name=userinfo['name'])
      db.session.add(new_user)
      db.session.commit()

    if error is None:
      session.clear()
      session['user_id'] = user.id

    user.logged_in_times += 1
    session['last_session_time'] = datetime.now()
    db.session.commit()
    print('Google User', userinfo)
    return redirect(url_for('core.home'))


class AuthFacebook(MethodResource, Resource):
  """Facebook Auth class"""
  @doc(description='Facebook auth setting and sign in function', tags=['Auth_Facebook'])
  def get(self):
    """facebook auth setting"""
    facebook_client_id = '627547808979705'
    facebook_client_secret = '7b88166525190071ef0158e9fdd10e01'
    oauth.register(
      name='facebook',
      client_id=facebook_client_id,
      client_secret=facebook_client_secret,
      access_token_url='https://graph.facebook.com/oauth/access_token',
      access_token_params=None,
      authorize_url='https://www.facebook.com/dialog/oauth',
      authorize_params=None,
      api_base_url='https://graph.facebook.com/',
      client_kwargs={'scope': 'email'},
    )
    redirect_uri = url_for('authfacebooklogin', _external=True)
    return oauth.facebook.authorize_redirect(redirect_uri)


class AuthFacebookLogin(MethodResource, Resource):
  """Get Facebook User Info"""
  @doc(description='Facebook authentication', tags=['Auth_Facebook'])
  def get(self):
    """redirect and get token user info"""
    token = oauth.facebook.authorize_access_token()
    resp = oauth.facebook.get('https://graph.facebook.com/me?fields=id,name,email,picture{url}')
    profile = resp.json()

    error = None
    user = Users.query.filter_by(email=profile['email']).first()

    if user is None:
      new_user = Users(email=profile['email'], name=profile['name'])
      db.session.add(new_user)
      db.session.commit()

    if error is None:
      session.clear()
      session['user_id'] = user.id

    user.logged_in_times += 1
    session['last_session_time'] = datetime.now()
    db.session.commit()

    session['email'] = profile['email']
    print('Facebook User', profile)

    return redirect(url_for('core.home'))


@core_bp.before_app_request
def load_logged_in_user():
  """get session for user that has logged in before"""
  user_id = session.get('user_id')
  print('USER', user_id)

  if user_id is None:
    g.user = None
  else:
    g.user = Users.query.filter_by(id=user_id).first()


class AuthSignOut(MethodResource, Resource):
  """Signout class"""
  @doc(description='Sign out function', tags=['Auth'])
  def get(self):
    """signout get method"""
    session.clear()
    return redirect(url_for('core.home'))


def login_required(view):
  """login required function"""
  @functools.wraps(view)
  def wrapped_view(*args, **kwargs):
    if g.user is None:
      return redirect(url_for('authsign'))
    return view(**kwargs)

  return wrapped_view


class ChangeProfileName(MethodResource, Resource):
  """Change Profile Name"""
  @doc(description='Change user profile name function', tags=['Profile'], security=['basicAuth', 'Oauth2', 'openId'])
  @login_required
  def get():
    """get change profile name page"""
    return make_response(render_template('auth/changeprofile.html'))


  @doc(description='Change user profile name function', tags=['Profile'], security=['basicAuth', 'Oauth2', 'openId'])
  @use_kwargs({'name': fields.Str(required=True)}, location=('form'))
  @marshal_with(UserSchema)
  @login_required
  def post(**_kwargs):
    """change user profile name function"""
    user_id = session.get('user_id')
    name_to_update = Users.query.get_or_404(user_id)
    name_to_update.name = request.form['name']
    db.session.commit()
    return redirect(url_for('userprofile'))
