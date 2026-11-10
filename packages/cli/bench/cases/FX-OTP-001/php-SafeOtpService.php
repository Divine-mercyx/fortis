<?php

class SafeOtpService
{
    public function makeOtp()
    {
        $otp = random_int(100000, 999999);
        return $otp;
    }

    public function respond()
    {
        return response()->json(['sent' => true]);
    }
}
