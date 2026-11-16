<?php

use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('cards', function (Blueprint $table) {
            $table->id();
            $table->string('card_number'); // @hit
            $table->string('cvv', 4); // @hit
            $table->string('last4');
            $table->string('brand');
            $table->string('authorization_code');
        });
    }
};
