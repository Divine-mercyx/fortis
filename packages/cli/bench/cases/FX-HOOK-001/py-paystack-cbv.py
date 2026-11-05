class PaystackWebhookView(View):
    def post(self, request):  # @hit
        credit(json.loads(request.body))
        return HttpResponse(status=200)
