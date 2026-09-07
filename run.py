"""
Entry point. Run with: python run.py
Loads .env first so app/config.py can read the environment variables.
"""
import os
from dotenv import load_dotenv

load_dotenv()

from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    app.run(debug=True)
