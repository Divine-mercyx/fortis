<?php

Route::post('/pin/forgot', function (Request $request) {
    $code = rand(1000, 9999); // @hit
    $link = $request->root() . '/pin/reset?code=' . $code; // @hit
    Log::info('pin reset', ['code' => $code]); // @hit
    return response()->json(['sent' => true, 'code' => $code]); // @hit
});

Route::post('/password/forgot', function (Request $request) {
    $token = Str::random(64);
    Mail::to($request->email)->send(new ResetMail(config('app.url') . '/reset/' . $token));
    return response()->json(['message' => 'If that account exists, we sent a link.']);
});
