import stripe
from flask import request

from .flutterwave import flutterwave


@app.post("/charge")
def charge():
    amount = request.json["amount"]
    result = stripe.Charge.create(amount=amount, currency="ngn")  # @hit
    return result


@app.post("/card")
def card():
    result = flutterwave.charge.card(  # @hit
        tx_ref=request.json["reference"],
        amount=request.json.get("amount"),
    )
    return result


@app.post("/session")
def session():
    return stripe.checkout.Session.create(amount=request.form["amount"])  # @hit
