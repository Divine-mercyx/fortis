@router.post("/webhooks/monnify")
def monnify_events(request: Request):
    verify_monnify_signature(request)
