<?php

// Paystack events
class SafeHmacWebhookController extends Controller
{
    public function handle(Request $request)
    {
        $signature = hash_hmac('sha512', $request->getContent(), config('services.paystack.secret'));
        abort_unless(hash_equals($signature, $request->header('x-paystack-signature')), 401);
    }
}
