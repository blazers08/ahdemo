"""dashboard module"""
from flask import render_template, session, make_response
from apps.auth import login_required
from apps.models import Users
from flask_restful import Resource
from flask_apispec.views import MethodResource
from flask_apispec import doc


class UserProfile(MethodResource, Resource):
  """Get User Profile"""
  @doc(description='Get UserProfile Page', tags=['Profile'], security=['basicAuth', 'Oauth2', 'openId'])
  @login_required
  def get():
    """get user profile page"""
    return make_response(render_template('auth/userprofile.html'))


class DashBoardList(MethodResource, Resource):
  """Dashboard Information"""
  @doc(description='Get dashboard informations', tags=['Profile'], security=['basicAuth', 'Oauth2', 'openId'])
  @login_required
  def get():
    """Get User Information"""
    user_id = session.get('user_id')
    print('profile user id', user_id)

    user_info = Users.query.get_or_404(user_id)
    user_stats = Users.query.count()

    return make_response(render_template('dashboard/dashboard.html', user_info=user_info, \
      user_stats=user_stats))
