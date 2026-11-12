<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class TokenService
{
    public function issue($user)
    {
        return JWT::encode(['sub' => $user->id], 'nolt-secret', 'HS256'); // @hit
    }

    public function issueForever($user)
    {
        return JWT::encode(['sub' => $user->id], config('jwt.secret'), 'HS256'); // @hit
    }

    public function read($jwt)
    {
        return JWT::decode($jwt, new Key(env('JWT_SECRET', 'changeme'), 'HS256')); // @hit
    }

    public function readHardcoded($jwt)
    {
        return JWT::decode($jwt, new Key('hard-coded-key', 'HS256')); // @hit
    }

    public function issueSafe($user)
    {
        return JWT::encode(['sub' => $user->id, 'exp' => time() + 900], config('jwt.secret'), 'HS256');
    }

    public function cookie()
    {
        setcookie('session', 'x', ['httponly' => false, 'secure' => true]); // @hit
    }
}
