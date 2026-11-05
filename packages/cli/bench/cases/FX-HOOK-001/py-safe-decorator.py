@bp.post("/webhooks/paystack")
@verify_webhook
def paystack_events():
    credit(request.json)
