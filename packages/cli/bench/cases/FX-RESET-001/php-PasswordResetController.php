<?php

class PasswordResetController extends Controller
{
    public function forgotPassword(Request $request)
    {
        $user = User::where('email', $request->email)->first();
        if (! $user) {
            abort(404, 'No account with that email'); // @hit
        }
        $token = md5(time() . $user->id); // @hit
        Mail::to($user)->send(new ResetMail($token));
        return response()->json(['ok' => true]);
    }

    public function resetPassword(Request $request) // @hit
    {
        $row = PasswordReset::where('token', $request->token)->first();
        $row->user->password = Hash::make($request->password);
        $row->user->save();
        return response()->json(['ok' => true]);
    }
}
