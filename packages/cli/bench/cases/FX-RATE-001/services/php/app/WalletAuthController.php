<?php
class WalletAuthController extends Controller
{
    public function __construct(private WalletLoginService $logins) {}
    public function login(Request $request)
    {
        return $this->logins->signIn($request->email, $request->password);
    }
}
