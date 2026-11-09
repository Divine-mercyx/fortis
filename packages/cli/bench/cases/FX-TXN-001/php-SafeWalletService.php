<?php

class SafeWalletService
{
    public function debit(int $id, int $amount)
    {
        DB::transaction(function () use ($id, $amount) {
            $wallet = Wallet::lockForUpdate()->find($id);
            $wallet->balance -= $amount;
            $wallet->save();
        });
    }

    public function locked(int $id, int $amount)
    {
        $wallet = Wallet::where('id', $id)->lockForUpdate()->first();
        $wallet->balance -= $amount;
        $wallet->save();
    }

    public function atomic(Wallet $wallet, int $amount)
    {
        $wallet->decrement('balance', $amount);
    }

    public function raw(Wallet $wallet, int $amount)
    {
        $wallet->update(['balance' => DB::raw("balance - {$amount}")]);
    }

    public function display(Wallet $wallet, int $amount)
    {
        $wallet->balance -= $amount;
        return $wallet->balance;
    }
}
