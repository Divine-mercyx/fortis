<?php
class CardAuthController extends Controller
{
    public function __construct(private CardLoginService $logins) {}
    public function login(Request $request)
    {
        return $this->logins->signIn($request->email, $request->password);
    }
}

class CardLoginService
{
    public function signIn($email, $password)
    {
        Log::info('login', ['email' => $email]);
        return Auth::attempt(['email' => $email, 'password' => $password]);
    }
}
