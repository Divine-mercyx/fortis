<?php

namespace App\Http\Controllers;

use Illuminate\Support\Str;

class PaymentController extends Controller
{
    public function pay($order)
    {
        $reference = 'TXN' . time(); // @hit
        $txRef = 'PAY-' . rand(100000, 999999); // @hit
        $paymentReference = uniqid('PW'); // @hit
        $payload = ['reference' => 'ORD' . mt_rand(), 'amount' => $order->total]; // @hit
        $safeRef = 'TXN-' . Str::uuid();
        $secureRef = 'TXN' . bin2hex(random_bytes(8));
        $randomRef = 'PAY-' . Str::random(16);
        $existing = $order->reference;
        $createdAt = time();
        $requestId = 'REQ' . time();
        $href = '/orders/' . time();
    }
}
