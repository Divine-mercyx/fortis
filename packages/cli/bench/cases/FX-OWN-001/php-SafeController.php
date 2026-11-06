<?php

class SafePaymentController extends Controller
{
    public function byPolicy($id)
    {
        $payment = Payment::findOrFail($id);
        $this->authorize('view', $payment);
        return $payment;
    }

    public function byGate($id)
    {
        $payment = Payment::findOrFail($id);
        Gate::authorize('view', $payment);
        return $payment;
    }

    public function byOwner($id)
    {
        return Payment::where('user_id', auth()->id())->findOrFail($id);
    }

    public function byRelation(Request $request, $id)
    {
        return $request->user()->payments()->findOrFail($id);
    }

    public function byAbort($id)
    {
        $payment = Payment::findOrFail($id);
        abort_unless($payment->user_id === auth()->id(), 404);
        return $payment;
    }

    public function profile($id)
    {
        return Profile::findOrFail($id);
    }
}
