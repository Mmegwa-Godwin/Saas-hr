# Saas-hr cleanup notes

This repo has moved to a cleaner startup pattern to make it easier to configure and maintain.

Key changes:
- `config.py` centralizes configuration and secret handling.
- `database.py` manages SQLite setup and schema bootstrapping.
- `app_factory.py` creates the app instance from the config and initializes the database once.
- `auth_helpers.py` contains reusable auth and CSRF validation helpers.

Quick start:
1. Copy `.env.example` to `.env`.
2. Set `SAAS_HR_SECRET_KEY` for local development.
3. Run with:
   `FLASK_APP=app_factory flask run`

This is a step toward a cleaner architecture, while preserving the existing application behavior.
