<?php

// Flutterwave and Monnify events
class PaymentsController extends Controller
{
    public function flutterwaveWebhook(Request $request) // @hit
    {
        return response()->noContent();
    }

    public function monnifyWebhook(Request $request) // @hit
    {
        return response()->noContent();
    }

    public function index()
    {
        return [];
    }
}
