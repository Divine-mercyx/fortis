from django.views.decorators.csrf import csrf_exempt


@csrf_exempt  # remita sends these
def remita_webhook(request):  # @hit
    credit(json.loads(request.body))
    return HttpResponse(status=200)
