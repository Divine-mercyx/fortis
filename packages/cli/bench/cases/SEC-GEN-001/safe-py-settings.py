import os
from decouple import config

SECRET_KEY = os.environ["SECRET_KEY"]
API_TOKEN = os.getenv("API_TOKEN")
JWT_SECRET = config("JWT_SECRET")
DEBUG_TOKEN = os.getenv("DEBUG_TOKEN", "not-set")
FALLBACK = os.getenv("API_TOKEN_NAME", "x-api-token-header")
LOCAL_DB = "postgresql://postgres:postgres@localhost:5432/wallet"
COMPOSE_DB = "postgresql://app:localpassword123@db:5432/wallet"
TEMPLATE_DB = f"postgresql://{user}:{password}@{host}/wallet"
ENV_DB = "postgresql://app:${DB_PASSWORD}@db.internal/wallet"
DOCS = "https://docs.example.com/guide"
EMAIL = "support@example.com"
