def paystack_webhook(request):
    check(request.META["HTTP_X_PAYSTACK_SIGNATURE"], request.body)
    return HttpResponse(status=200)
