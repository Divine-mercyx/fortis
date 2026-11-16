<?php
Route::post('wallet/login', [WalletAuthController::class, 'login']);
Route::post('card/login', [CardAuthController::class, 'login']); // @hit
