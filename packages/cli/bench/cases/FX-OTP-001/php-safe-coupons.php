<?php

class CouponRepository
{
    public function make()
    {
        $couponCode = 'SALE' . rand(1000, 9999);
        return $couponCode;
    }

    public function referral()
    {
        $referralCode = mt_rand(1000, 9999);
        return $referralCode;
    }
}
