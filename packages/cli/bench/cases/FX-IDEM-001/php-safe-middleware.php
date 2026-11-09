<?php

Route::post('/transfers', [TransferController::class, 'store'])
    ->middleware('dedup.requests');
