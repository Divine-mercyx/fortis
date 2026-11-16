<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ChargeController extends Controller
{
    public function stripe(Request $request)
    {
        return $this->stripe->paymentIntents->create(['amount' => $request->input('amount'), 'currency' => 'ngn']); // @hit
    }

    public function flutterwave(Request $request)
    {
        $validated = $request->validate(['amount' => 'required|numeric']);
        return $this->flutterwave->charge(['amount' => $validated['amount'], 'email' => $request->email]); // @hit
    }

    public function monnify()
    {
        $amount = $_POST['amount'];
        $payload = ['amount' => $amount, 'currencyCode' => 'NGN'];
        return $this->monnify->initializeTransaction($payload); // @hit
    }

    public function invoice(Request $request)
    {
        $invoice = Invoice::findOrFail($request->invoice_id);
        return $this->paystack->initialize(['amount' => $invoice->amount, 'email' => $request->email]);
    }

    public function subscription(Request $request)
    {
        $price = Pricing::for($request->plan);
        return $this->stripe->paymentIntents->create(['amount' => $price, 'currency' => 'ngn']);
    }
}
