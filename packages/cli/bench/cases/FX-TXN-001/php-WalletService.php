<?php

class WalletService
{
    public function debit(Wallet $wallet, int $amount)
    {
        $wallet->balance -= $amount; // @hit
        $wallet->save();
    }

    public function credit(Wallet $wallet, int $amount)
    {
        $wallet->balance = $wallet->balance + $amount; // @hit
        $wallet->save();
    }

    public function hold(Wallet $wallet, int $amount)
    {
        $wallet->available_balance -= $amount; // @hit
        $wallet->saveOrFail();
    }

    public function reverse(Wallet $wallet, int $amount)
    {
        $wallet->update(['balance' => $wallet->balance + $amount]); // @hit
    }

    public function settle(Account $account, int $amount)
    {
        $account->ledger_balance += $amount; // @hit
        $account->save();
    }
}
