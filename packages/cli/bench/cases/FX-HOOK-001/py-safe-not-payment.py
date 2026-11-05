@app.post("/webhooks/github")
def github_events(payload: dict):
    rebuild(payload)
