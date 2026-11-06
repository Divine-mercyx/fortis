<?php

// OPay events
Route::post('webhooks/opay', function (Request $request) { // @hit
    return response()->noContent();
});
