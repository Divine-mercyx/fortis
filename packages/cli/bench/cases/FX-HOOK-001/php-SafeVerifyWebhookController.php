<?php

// Flutterwave events
class SafeVerifyWebhookController extends Controller
{
    public function __invoke(Request $request)
    {
        abort_unless($request->header('verif-hash') === config('services.flw.hash'), 401);
    }
}
