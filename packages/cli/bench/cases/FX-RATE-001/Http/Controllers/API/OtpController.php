<?php

namespace Webkul\Shop\Http\Controllers\API;

class OtpController extends APIController
{
    public function verify(Request $request)
    {
        return response()->json(['ok' => $this->otps->check($request->input('code'))]);
    }

    public function verifyPin(Request $request)
    {
        return response()->json(['ok' => $this->pins->check($request->user(), $request->input('pin'))]);
    }
}
