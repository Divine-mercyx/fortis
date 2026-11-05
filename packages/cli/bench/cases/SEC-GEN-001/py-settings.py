import os
from decouple import config

SECRET_KEY = "{{GENERIC}}"  # @hit
PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET_KEY", "{{GENERIC}}")  # @hit
API_TOKEN = os.environ.get("API_TOKEN", "{{GENERIC}}")  # @hit
JWT_SECRET = config("JWT_SECRET", default="{{GENERIC}}")  # @hit
WEBHOOK_SECRET = env("WEBHOOK_SECRET", default="{{GENERIC}}")  # @hit
DATABASE_URL = "postgresql+psycopg2://wallet:{{GENERIC}}@db.internal:5432/wallet"  # @hit
BROKER_URL = "amqp://svc:{{GENERIC}}@mq.internal:5672//"  # @hit
DATABASES = {"default": {"PASSWORD": "{{GENERIC}}"}}  # @hit
