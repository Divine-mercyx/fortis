<?php

// Each request carries an Idempotency-Key header.
Route::post('/transfers', [TransferController::class, 'store']);
