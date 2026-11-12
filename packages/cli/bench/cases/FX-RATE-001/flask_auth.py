from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():  # @hit
    return jsonify(auth.login(request.json["email"], request.json["password"]))


@app.route("/otp/verify", methods=["POST"])
def verify_otp():  # @hit
    return jsonify(auth.verify_otp(request.json["phone"], request.json["otp"]))


@app.route("/otp/resend", methods=["POST"])
@limiter.limit("3/minute")
def resend_otp():
    return jsonify(auth.resend_otp(request.json["phone"]))


@app.route("/logout", methods=["POST"])
def logout():
    return jsonify(auth.logout())
