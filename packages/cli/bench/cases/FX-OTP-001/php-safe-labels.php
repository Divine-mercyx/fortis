<?php

class Limiter
{
    public function reserve()
    {
        $token = uniqid('req_', true);
        return $token;
    }
}
