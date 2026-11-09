import requests

from .monnify import monnify
from .squad import squad_client


def pay(request):
    return monnify.initialize(amount=request.data["amount"], email=request.user.email)  # @hit


def pay_squad(request):
    amount = request.POST["amount"]
    return squad_client.initiate(amount=amount, email=request.user.email)  # @hit


def pay_paystack(request):
    return requests.post(  # @hit
        "https://api.paystack.co/transaction/initialize",
        json={"amount": request.json["amount"], "email": request.user.email},
    )
