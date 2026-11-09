import secrets
import time
import uuid


# Flutterwave payments
def references(order):
    reference = str(uuid.uuid4())
    tx_ref = secrets.token_hex(16)
    timed = f"{time.time()}-{uuid.uuid4()}"
    started_at = time.time()
    delay = random.random()
    transfer_ref = order.reference
    return reference, tx_ref, timed, started_at, delay, transfer_ref
