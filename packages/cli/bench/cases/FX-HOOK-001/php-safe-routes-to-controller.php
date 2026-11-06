<?php

// Paystack events are checked in the controller.
Route::post('/paystack/webhook', [PaystackWebhookController::class, 'handle']);
