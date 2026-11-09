<?php

// Remita, Kora and Interswitch notifications
Route::post('/remita/webhook', function (Request $request) { // @hit
    return response()->noContent();
});
Route::any('/kora/webhook', fn (Request $request) => response()->noContent()); // @hit
Route::post('webhooks/interswitch', static function (Request $request) { // @hit
    return response()->noContent();
});
Route::get('/remita/webhook/health', function () {
    return 'ok';
});
