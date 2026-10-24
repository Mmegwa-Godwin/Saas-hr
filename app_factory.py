import os

from flask import Flask

from config import AppConfig
from database import close_db, init_db


def create_app():
    app = Flask(__name__)
    app.config.from_object(AppConfig)
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("SAAS_HR_DEBUG", "").lower() == "true",
    )
