@app.post("/webhooks/paystack")
async def paystack_events(request: Request):
    body = await request.body()
    expected = hmac.new(SECRET, body, hashlib.sha512).hexdigest()
    if not hmac.compare_digest(expected, request.headers["x-paystack-signature"]):
        raise HTTPException(401)
