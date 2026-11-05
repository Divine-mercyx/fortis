@app.post("/paystack/initialize")
def start_payment(payload: dict):
    return paystack.initialize(payload)
