@router.post("/webhooks/paystack")  # @hit
async def paystack_events(payload: dict):
    await credit(payload)
