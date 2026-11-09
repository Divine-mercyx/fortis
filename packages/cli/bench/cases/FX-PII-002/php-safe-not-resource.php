<?php

class KycRequestMapper
{
    public function toProvider(Customer $customer)
    {
        return ['bvn' => $customer->bvn];
    }
}
