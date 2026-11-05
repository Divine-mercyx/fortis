@router.post("/transfers")  # @hit
def create_transfer(payload: dict):
    return move_money(payload)


@app.post("/api/payouts")  # @hit
async def payout(payload: dict):
    return await pay(payload)


@bp.route("/withdrawals", methods=["POST"])  # @hit
def withdraw():
    return pay(request.json)


@bp.post("/send-money")  # @hit
def send():
    return pay(request.json)


@bp.route(  # @hit
    "/disbursements",
    methods=["GET", "POST"],
)
def disburse():
    return pay(request.json)


class TransferView(APIView):
    def post(self, request):  # @hit
        return Response(pay(request.data))


@api_view(["POST"])
def wallet_transfer(request):  # @hit
    return Response(pay(request.data))


def payout_view(request):  # @hit
    if request.method == "POST":
        pay(request.POST)
    return HttpResponse()


class WalletViewSet(ViewSet):
    @action(detail=True, methods=["post"])
    def withdraw(self, request, pk=None):  # @hit
        return Response(pay(request.data))
