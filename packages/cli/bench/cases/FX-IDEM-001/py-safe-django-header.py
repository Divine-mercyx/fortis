class TransferView(APIView):
    def post(self, request):
        key = request.META["HTTP_IDEMPOTENCY_KEY"]
        return Response(pay(request.data, key))
