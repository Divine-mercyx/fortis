<?php

use Illuminate\Support\Facades\Route;
use Webkul\Shop\Http\Controllers\API\CustomerController;
use Webkul\Shop\Http\Controllers\API\OtpController;

Route::group(['prefix' => 'api'], function () {
    // The controller limits attempts itself (hasTooManyLoginAttempts).
    Route::controller(CustomerController::class)->prefix('customer')->group(function () {
        Route::post('login', 'login')->name('shop.api.customers.session.create');
    });

    // This one doesn't.
    Route::controller(OtpController::class)->prefix('otp')->group(function () {
        Route::post('verify', 'verify'); // @hit
    });

    Route::post('pin/verify', [OtpController::class, 'verifyPin']); // @hit
});

Route::middleware(['auth', 'admin'])->prefix('admin')->group(function () {
    Route::post('customers/{id}/password/reset', [CustomerController::class, 'sendReset']);
});
