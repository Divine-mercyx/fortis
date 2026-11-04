@router.post("/transfers/quote")
def quote(payload: dict):
    return fee_for(payload)


@router.post("/transfers/name-enquiry")
def name_enquiry(payload: dict):
    return lookup(payload)


@router.get("/transfers")
def list_transfers():
    return []


@router.post("/users")
def create_user(payload: dict):
    return save(payload)


class TransferHistoryView(APIView):
    def get(self, request):
        return Response([])


def transfer_page(request):
    return render(request, "transfer.html")


def transfer_money(wallet, amount):
    return pay(wallet, amount)


class ReportView(APIView):
    def post(self, request):
        return Response(build(request.data))
