import stripe

from .paystack import paystack


def checkout(request):
    result = paystack.transaction.initialize(  # @hit
        email=request.user.email,
        amount=request.data["amount"],
    )
    return Response(result)


def pay(request):
    amount = request.data["amount"]
    result = paystack.transaction.initialize(email=request.user.email, amount=amount)  # @hit
    return Response(result)


def intent(request):
    charge = stripe.PaymentIntent.create(amount=request.data["amount"], currency="ngn")  # @hit
    return Response(charge)
