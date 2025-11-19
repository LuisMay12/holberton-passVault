import os
from dotenv import load_dotenv

load_dotenv()

class BaseConfig:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_TYPE = os.getenv("SESSION_TYPE", "filesystem")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
    JWT_EXP_MINUTES = 10
    JWT_ALGORITHM = "HS256"
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = 3600 
    PREFERRED_URL_SCHEME = "https"

class DevConfig(BaseConfig):
    DEBUG = True

class ProdConfig(BaseConfig):
    DEBUG = False
