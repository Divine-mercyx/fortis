<?php

class SafeInvoiceController extends Controller
{
    public function __construct()
    {
        $this->authorizeResource(Invoice::class);
    }

    public function show($id)
    {
        return Invoice::findOrFail($id);
    }
}
