<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class CheckoutController extends Controller
{
    public function pay(Request $request)
    {
        return Http::withToken(config('services.paystack.secret'))->post('https://api.paystack.co/transaction/initialize', [ // @hit
            'email' => $request->email,
            'amount' => $request->amount * 100,
        ]);
    }

    public function order(Request $request)
    {
        $amount = $request->input('amount');
        return $this->paystack->initialize(['email' => $request->email, 'amount' => $amount]); // @hit
    }

    public function plan(Request $request)
    {
        $plan = Plan::findOrFail($request->plan_id);
        return $this->paystack->initialize(['email' => $request->email, 'amount' => $plan->price_kobo]);
    }

    public function cart(Request $request)
    {
        $total = Cart::totalFor($request->user());
        return Http::post('https://api.paystack.co/transaction/initialize', ['email' => $request->email, 'amount' => $total]);
    }
}
