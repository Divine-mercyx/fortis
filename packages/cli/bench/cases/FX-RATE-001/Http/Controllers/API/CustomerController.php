<?php

namespace Webkul\Shop\Http\Controllers\API;

use Illuminate\Foundation\Auth\ThrottlesLogins;

class CustomerController extends APIController
{
    use ThrottlesLogins;

    public function login(LoginRequest $request)
    {
        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        if (! auth()->guard('customer')->attempt($request->only(['email', 'password']))) {
            $this->incrementLoginAttempts($request);

            return response()->json(['message' => 'Invalid credentials'], 403);
        }

        $this->clearLoginAttempts($request);

        return response()->json(['data' => auth()->guard('customer')->user()]);
    }
}
