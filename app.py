from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    app.config['SECRET_KEY'] = 'replace_me'

    from models import db

    import models
    models.init_app(app)

    import auth
    auth.init_app(app, db)
    app.register_blueprint(auth.blueprint)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run()