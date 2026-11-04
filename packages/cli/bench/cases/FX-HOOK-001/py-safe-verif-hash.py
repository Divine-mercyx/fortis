@app.post("/flutterwave/webhook")
def flutterwave_events(request: Request):
    if request.headers.get("verif-hash") != FLUTTERWAVE_HASH:
        raise HTTPException(401)
