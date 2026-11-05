@app.route("/webhooks/paystack", methods=["POST"])  # @hit
def paystack_events():
    credit(request.get_json())
    return "", 200
