<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('wallets', function (Blueprint $table) {
            $table->id();
            $table->float('balance'); // @hit
            $table->double('available_balance', 15, 2); // @hit
            $table->float('fee'); // @hit
            $table->decimal('ledger_balance', 15, 2);
            $table->bigInteger('balance_kobo');
            $table->float('interest_rate');
            $table->float('latitude');
            $table->string('amount_label');
        });
    }
};

class TransferService
{
    private float $balance; // @hit
    private int $balanceKobo;
    private float $interestRate;

    public function send(float $amount, string $account): void {}

    public function parse($request): void
    {
        $amount = floatval($request->amount); // @hit
        $total = (float) $request->total;
        $kobo = (int) round(floatval($request->amount) * 100);
        $ratio = floatval($request->ratio);
        $shown = number_format($this->balance, 2);
        $negative = floatval($request->amount) < 0;
    }
}

class Formatter
{
    /**
     * @param  float  $amount
     */
    public function formatPrice(?float $price, ?string $currency = null): string
    {
        if (! (float) $price) return '';
        return number_format((float) $price, 2);
    }
}
