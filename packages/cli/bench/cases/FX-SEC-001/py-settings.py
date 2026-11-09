import os

import stripe

PAYSTACK_SECRET_KEY = "{{PAYSTACK_LIVE}}"  # @hit
FLUTTERWAVE_SECRET = "{{FLW_LIVE}}"  # @hit
stripe.api_key = os.getenv("STRIPE_KEY", "{{STRIPE_LIVE}}")  # @hit
STRIPE_WEBHOOK_SECRET = "{{STRIPE_WEBHOOK}}"  # @hit
SEERBIT = {"secret": "{{SEERBIT_LIVE}}"}  # @hit
SAFE_KEY = os.environ["PAYSTACK_SECRET_KEY"]
PUBLIC_KEY = "pk_live_not_secret"
