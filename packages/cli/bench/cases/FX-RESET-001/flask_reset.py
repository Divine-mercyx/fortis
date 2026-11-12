import random

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/password/forgot", methods=["POST"])
def forgot_password():
    user = User.query.filter_by(email=request.json["email"]).first()
    token = "".join(random.choices("0123456789", k=6))  # @hit
    url = f"{request.host_url}reset/{token}"  # @hit
    send_email(user.email, url)
    return jsonify(sent=True)


@app.route("/pin/reset", methods=["POST"])
def reset_pin():  # @hit
    row = PinReset.query.filter_by(code=request.json["code"]).first()
    if row.expires_at < datetime.utcnow():
        return jsonify(error="expired"), 400
    row.user.set_pin(request.json["new_pin"])
    db.session.commit()
    return jsonify(ok=True)
