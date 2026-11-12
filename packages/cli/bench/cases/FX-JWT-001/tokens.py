import os
from datetime import datetime, timedelta

import jwt

SECRET = os.getenv("JWT_SECRET", "nolt-secret")  # @hit
KEY = os.environ["JWT_SECRET"]


def issue_forever(user_id):
    return jwt.encode({"sub": user_id}, KEY, algorithm="HS256")  # @hit


def issue(user_id):
    payload = {"sub": user_id, "exp": datetime.utcnow() + timedelta(minutes=15)}
    return jwt.encode(payload, KEY, algorithm="HS256")


def issue_hardcoded(user_id):
    return jwt.encode({"sub": user_id, "exp": 1}, "hard-coded-key", algorithm="HS256")  # @hit


def read_unverified(token):
    return jwt.decode(token, options={"verify_signature": False})  # @hit


def read_expired(token):
    return jwt.decode(token, KEY, algorithms=["HS256"], options={"verify_exp": False})  # @hit


def read(token):
    return jwt.decode(token, KEY, algorithms=["HS256"])
