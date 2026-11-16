<?php
class WalletLoginService
{
    public function __construct(private WalletLoginGuard $guard) {}
    public function signIn($email, $password)
    {
        $this->guard->check($email);
        return Auth::attempt(['email' => $email, 'password' => $password]);
    }
}

class WalletLoginGuard
{
    public function check($key)
    {
        if (RateLimiter::tooManyAttempts('login:'.$key, 5)) { abort(429); }
        RateLimiter::hit('login:'.$key);
    }
}
