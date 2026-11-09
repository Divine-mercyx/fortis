<?php

class KycService
{
    public function verify(Customer $customer, string $bvn, string $nin)
    {
        Log::info('checking', ['bvn' => $bvn]); // @hit
        Log::error("failed for {$customer->nin}"); // @hit
        logger('lookup', ['value' => $customer->bvn]); // @hit
        logger()->debug("bvn $bvn"); // @hit
        error_log('nin ' . $nin); // @hit
        Log::warning('retry', [ // @hit
            'customer' => $customer->id,
            'national_id' => $customer->national_id,
        ]);

        Log::info('checking bvn');
        Log::info('has', ['has' => filled($bvn)]);
        Log::info('set', ['set' => isset($customer->bvn)]);
        Log::info('bvn', ['bvn' => Str::mask($bvn, '*', 0, 7)]);
        Log::info('id', ['id' => $customer->id]);
    }
}
