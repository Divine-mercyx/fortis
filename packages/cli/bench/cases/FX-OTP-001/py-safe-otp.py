import random
import secrets


def generate_otp():
    return secrets.randbelow(900000) + 100000


def generate_token():
    return secrets.token_urlsafe(32)


def shuffle_cards(deck):
    return random.choice(deck)


def jitter():
    return random.random() * 2


def sent_message():
    logger.info("OTP sent")


def masked(otp):
    logger.info("otp %s", mask(otp))


def response_without_value():
    return JsonResponse({"otp_sent": True})


def response_text():
    return {"otp": "sent"}


def length_rule():
    OTP_LENGTH = 6
    return OTP_LENGTH
