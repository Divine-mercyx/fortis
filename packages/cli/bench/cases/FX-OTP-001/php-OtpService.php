<?php

class OtpService
{
    public function makeOtp()
    {
        $otp = rand(100000, 999999); // @hit
        return $otp;
    }

    public function resetToken()
    {
        $resetToken = mt_rand(100000, 999999); // @hit
        return $resetToken;
    }

    public function verificationCode()
    {
        return mt_rand(1000, 9999); // @hit
    }

    public function send(string $otp, string $phone)
    {
        Log::info("otp for $phone: $otp"); // @hit
        logger('sent', ['otp' => $otp]); // @hit
        return response()->json(['sent' => true, 'otp' => $otp]); // @hit
    }

    public function review()
    {
        Log::info('reviewer otp is 482901'); // @hit
    }

    public function delay()
    {
        $delay = rand(1, 100);
        return $delay;
    }

    public function notice()
    {
        Log::info('otp sent');
    }
}
