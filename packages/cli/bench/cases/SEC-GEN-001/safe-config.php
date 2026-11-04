<?php
return [
    'api_key' => env('PAYMENT_API_KEY'),
    'secret' => $_ENV['PAYMENT_SECRET_VALUE'],
    'password_hint' => 'use-at-least-ten-characters',
    'token_url' => 'https://auth.example.com/oauth/token',
];
