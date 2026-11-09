<?php

Route::post('/transfers', [TransferController::class, 'store']); // @hit
Route::post('wallets/{wallet}/withdraw', [WalletController::class, 'withdraw']); // @hit
Route::put('/payouts/{id}', [PayoutController::class, 'update']); // @hit
Route::post('/loans/disbursements', [LoanController::class, 'disburse']); // @hit
Route::post('send-money', [SendController::class, 'store']); // @hit
$router->post('/v1/transfers', 'TransferController@store'); // @hit

Route::post('/transfers/quote', [TransferController::class, 'quote']);
Route::post('/payouts/name-enquiry', [PayoutController::class, 'enquiry']);
Route::get('/transfers', [TransferController::class, 'index']);
Route::post('/profile', [ProfileController::class, 'update']);
Route::post('/stores/{id}/payout-processors', [ProcessorController::class, 'store']);
Route::post('/payouts/{id}/mark-paid', [PayoutController::class, 'markPaid']);
