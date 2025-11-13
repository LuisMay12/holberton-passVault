from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_session import Session
from flask_cors import CORS

db = SQLAlchemy()
migrate = Migrate()
# login_manager = LoginManager()
server_session = Session()
cors = CORS()
