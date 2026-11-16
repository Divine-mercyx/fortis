<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class CardController extends Controller
{
    public function charge(Request $request)
    {
        Log::info('charging card', ['card' => $request->card_number]); // @hit
        Log::debug("cvv {$request->cvv}"); // @hit
        error_log('pan ' . $data['card_number']); // @hit
        logger('card', $request->input('cvv')); // @hit
        Log::info('charging card ending ' . substr($request->card_number, -4));
        Log::info('has cvv', ['present' => isset($data['cvv'])]);
        Log::info('card brand', ['brand' => $request->brand]);
        Log::warning('declined', ['message' => $response['message']]);
        $number = $request->card_number;
    }
}
