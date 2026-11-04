@api_view(["POST"])
def kora_webhook(request):  # @hit
    credit(request.data)
    return Response(status=200)
