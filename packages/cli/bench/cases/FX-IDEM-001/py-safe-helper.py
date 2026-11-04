@router.post("/payouts")
@with_payment_guard
def create_payout(payload: dict):
    return pay(payload)
