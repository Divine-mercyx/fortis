<?php

class SafeGithubWebhookController extends Controller
{
    public function handle(Request $request)
    {
        return response()->noContent();
    }
}
