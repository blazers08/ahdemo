"""init settings for flask"""
from flask import Flask
from flask_restful import Api
from apispec import APISpec
from apispec.ext.marshmallow import MarshmallowPlugin
from flask_apispec.extension import FlaskApiSpec
from authlib.integrations.flask_client import OAuth
from . import auth, dashboard, models


def create_app():
  """create and configure the app"""
  app = Flask(__name__, instance_relative_config=True)
  app.config.from_mapping(
    SECRET_KEY='dev',
    SQLALCHEMY_DATABASE_URI='postgresql://blfiupjoxhpuhw:5338a5847c75cc195a6b6aec5aa4df3a6e9807237c54c4d85605466142decda7@ec2-3-229-165-146.compute-1.amazonaws.com:5432/dek82kc2s2qp9p',
  )


  api_key_scheme = {
    'securitySchemes':{
      'basicAuth':{
        'type': 'http',
        'scheme': 'basic'
      },
      'GoogleOpenId':{
        'openIdConnectUrl':'https://accounts.google.com/.well-known/openid-configuration',
        'type':'openIdConnect'
      },
      'Oauth2': {
        'type': 'oauth2',
        'description': 'Facebook OAuth',
        'flows': {
          'clientCredentials':{
            'authorizationUrl': 'https://www.facebook.com/dialog/oauth',
            'tokenUrl': 'https://graph.facebook.com/oauth/access_token',
            'refreshUrl': 'https://dennydemo.herokuapp.com/facebook/login',
            'scopes': ['email']
          }
        }
      },
      # "Oauth2":{
      #   "description":"Facebook OAuth",
      #   "flows":{
      #      "authorizationCode":{
      #         "authorizationUrl":"https://www.facebook.com/dialog/oauth",
      #         "scopes":[
      #            "email"
      #         ],
      #         "tokenUrl":"https://graph.facebook.com/oauth/access_token"
      #      }
      #   },
      #   "type":"oauth2"
      # }
    }
  }

  app.config.update({
    'APISPEC_SPEC': APISpec(
        title='Ah! Demo',
        version='1.0.0',
        plugins=[MarshmallowPlugin()],
        openapi_version='3.0.2',
        components=(api_key_scheme)
    ),
    'APISPEC_SWAGGER_URL': '/swagger/',  # URI to access API Doc JSON
    'APISPEC_SWAGGER_UI_URL': '/swagger-ui/'  # URI to access UI of API Doc
  })

  api = Api(app)
  docs = FlaskApiSpec(app)
  models.db.init_app(app)
  models.ma.init_app(app)
  auth.oauth.init_app(app)

  api.add_resource(auth.AuthSign, '/sign', methods=['POST', 'GET'])
  api.add_resource(auth.AuthSignOut, '/signout', methods=['GET'])
  api.add_resource(auth.AuthRegister, '/signup', methods=['POST', 'GET'])
  api.add_resource(auth.AuthGoogle, '/google', methods=['GET'])
  api.add_resource(auth.AuthGoogleLogin, '/google/login', methods=['GET'])
  api.add_resource(auth.AuthFacebook, '/facebook', methods=['GET'])
  api.add_resource(auth.AuthFacebookLogin, '/facebook/login', methods=['GET'])
  api.add_resource(auth.ChangeProfileName, '/changeprofile', methods=['POST', 'GET'])
  api.add_resource(dashboard.UserProfile, '/profile', methods=['GET'])
  api.add_resource(dashboard.DashBoardList, '/dashboard', methods=['GET'])

  docs.register(auth.AuthSign)
  docs.register(auth.AuthSignOut)
  docs.register(auth.AuthRegister)
  docs.register(auth.AuthGoogle)
  docs.register(auth.AuthGoogleLogin)
  docs.register(auth.AuthFacebook)
  docs.register(auth.AuthFacebookLogin)
  docs.register(auth.ChangeProfileName)
  docs.register(dashboard.UserProfile)
  docs.register(dashboard.DashBoardList)

  app.register_blueprint(auth.core_bp)
  app.register_blueprint(auth.api_bp, url_prefix='/api')
  app.add_url_rule('/', endpoint='home')

  return app
