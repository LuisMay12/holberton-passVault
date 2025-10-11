import os

class BaseConfig:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_TYPE = os.getenv("SESSION_TYPE", "filesystem")
    SESSION_PERMANENT = True
    PERMANENT_SESSION_LIFETIME = 3600 
    PREFERRED_URL_SCHEME = "https"

class DevConfig(BaseConfig):
    DEBUG = True

class ProdConfig(BaseConfig):
    DEBUG = False
