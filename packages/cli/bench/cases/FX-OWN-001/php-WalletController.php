<?php

class WalletController extends Controller
{
    public function show($id)
    {
        $wallet = $this->wallets->findOrFail($id); // @hit
        return new WalletResource($wallet);
    }

    public function transactions($walletId)
    {
        return Transaction::find($walletId); // @hit
    }

    public function card(Request $request)
    {
        return Card::findOrFail($request->input('id')); // @hit
    }
}
