from app import create_app
from app.db import init_db

app = create_app()


if __name__ == '__main__':
    """Initialize storage and run the development server."""
    with app.app_context():
        init_db(app.config['DATABASE_PATH'])
    app.run(host='0.0.0.0', port=5000)
