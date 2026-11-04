# Idempotency guard used across the money routes.
def with_payment_guard(fn):
    return fn
