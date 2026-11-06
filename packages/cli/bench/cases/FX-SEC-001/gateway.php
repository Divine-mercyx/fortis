<?php
$paystack = new Paystack('{{PAYSTACK_LIVE}}'); // @hit
$flutterwave = ['secret' => '{{FLW_LIVE}}']; // @hit
$fromEnv = getenv('PAYSTACK_SECRET_KEY');
