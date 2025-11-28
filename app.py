import os
from flask import Flask
from dotenv import load_dotenv
from config import DevConfig, ProdConfig
from extensions import db, migrate, cors # login_manager, server_session
from models import User
from flasgger import Swagger

def create_app():
    load_dotenv()
    app = Flask(__name__)
    app.config.from_object(ProdConfig if os.getenv("FLASK_ENV") == "production" else DevConfig)

    # Init extensions
    db.init_app(app)
    migrate.init_app(app, db)
    # login_manager.init_app(app)
    # server_session.init_app(app)
    
    # Configure CORS for frontend
    allowed_origins = os.getenv(CORS_ORIGINS, "http://password-vault-frontend.vercel.app").split(",")
    cors.init_app(app, resources={
        r"/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })

    # For session auth
    # @login_manager.user_loader
    # def load_user(user_id):
    #     return User.query.get(user_id)

    # login_manager.login_view = "auth.login"

    @app.after_request
    def set_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    # Register blueprints
    from blueprints.auth.routes import bp as auth_bp
    from blueprints.vault.routes import bp as vault_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(vault_bp, url_prefix="/vault")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app

app = create_app()

if __name__ == "__main__":
    # app = create_app()
    app.run()
