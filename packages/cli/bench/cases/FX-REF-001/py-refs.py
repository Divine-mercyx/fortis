import random
import time
from datetime import datetime


# Flutterwave payments
def references(order):
    reference = f"TX-{int(time.time())}"  # @hit
    tx_ref = "FLW-" + str(random.randint(1000, 9999))  # @hit
    payment_reference = f"pay_{datetime.now().timestamp()}"  # @hit
    transfer_ref = str(random.random())  # @hit
    order_ref = f"{order.id}-{time.time_ns()}"  # @hit
    return {
        "tx_ref": tx_ref,
    }


def more():
    payout_reference = str(datetime.utcnow().timestamp())  # @hit
    merchant_ref = random.choice(CODES)  # @hit
    charge_ref = time.time()  # @hit
    return payout_reference, merchant_ref, charge_ref
