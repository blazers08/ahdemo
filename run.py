"""start the flask app"""
import os
from apps import create_app

app = create_app()

if __name__ == '__main__':
  PORT = os.environ.get('PORT', 5000)
  app.run(host='0.0.0.0', port=PORT, debug=True)
