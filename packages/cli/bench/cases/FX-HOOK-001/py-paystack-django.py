def paystack_webhook(request):  # @hit
    event = json.loads(request.body)
    credit(event)
    return HttpResponse(status=200)
