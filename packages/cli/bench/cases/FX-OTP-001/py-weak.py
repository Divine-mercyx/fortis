import random


def generate_otp():
    return random.randint(100000, 999999)  # @hit


def make_code():
    otp = "".join(random.choices("0123456789", k=6))  # @hit
    return otp


def reset_pin():
    pin = random.randrange(1000, 9999)  # @hit
    return pin


def verification():
    return random.choice(CODES)  # @hit


def log_it(otp):
    logger.info(f"OTP is {otp}")  # @hit


def print_it(user):
    print(user.otp_code)  # @hit


def hardcoded():
    otp = "123456"  # @hit
    return otp


def respond(otp):
    return JsonResponse({"otp": otp})  # @hit


def respond_drf(code):
    return Response({"status": "sent", "otp": code})  # @hit


def respond_flask(otp):
    return jsonify(status="sent", otp=otp)  # @hit


def respond_dict(otp):
    return {"otp": otp}  # @hit
