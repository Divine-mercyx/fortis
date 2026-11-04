def register_paystack_webhook(client):
    client.post("/webhooks", json={"url": URL})
