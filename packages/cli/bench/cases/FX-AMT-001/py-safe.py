import stripe

from .paystack import paystack


def checkout(request):
    order = Order.objects.get(pk=request.data["order"], user=request.user)
    return paystack.transaction.initialize(email=request.user.email, amount=order.total)


def subscribe(request):
    plan = PLANS[request.data["plan"]]
    return stripe.PaymentIntent.create(amount=plan.price, currency="ngn")


def fund_wallet(request):
    # Choosing how much to add is the point of funding a wallet.
    return paystack.transaction.initialize(email=request.user.email, amount=request.data["amount"])


def verify(request):
    amount = request.data["amount"]
    return paystack.transaction.verify(request.data["reference"])
