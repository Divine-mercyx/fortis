@bp.post("/monnify/webhook")  # @hit
def monnify_events():
    credit(request.json)
    return "", 200
