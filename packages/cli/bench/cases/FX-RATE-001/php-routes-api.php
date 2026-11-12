<?php

use Illuminate\Support\Facades\Route;

Route::post('/login', [AuthController::class, 'login']); // @hit
Route::post('/register', [AuthController::class, 'register']);
Route::post('/otp/verify', [OtpController::class, 'verify']); // @hit
Route::post('/otp/resend', [OtpController::class, 'resend'])->middleware('throttle:3,1');
Route::post('/pin/verify', [PinController::class, 'verify']); // @hit
Route::post('/password/forgot', [PasswordController::class, 'forgot']); // @hit
Route::middleware(['auth:sanctum', 'throttle:pin'])->group(function () {
    Route::post('/pin/change', [PinController::class, 'change']);
    Route::post('/2fa/verify', [TwoFactorController::class, 'verify']);
});
Route::post('/sign-in/phone', [AuthController::class, 'phoneLogin']); // @hit
Route::post('/transfers', [TransferController::class, 'store']);
