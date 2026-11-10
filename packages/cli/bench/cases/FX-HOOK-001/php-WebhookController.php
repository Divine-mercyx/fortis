<?php

// Paystack events
class PaystackWebhookController extends Controller
{
    public function handle(Request $request) // @hit
    {
        Wallet::credit($request->input('data.amount'));
    }
}
