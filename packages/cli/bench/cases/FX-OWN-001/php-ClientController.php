<?php

class ClientController extends Controller
{
    public function show($clientId)
    {
        return Client::find($clientId);
    }
}
