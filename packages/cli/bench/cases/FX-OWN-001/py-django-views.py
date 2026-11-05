from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from rest_framework.decorators import api_view
from rest_framework.generics import RetrieveAPIView
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet


def transfer_detail(request, pk):
    transfer = Transfer.objects.get(pk=pk)  # @hit
    return JsonResponse({"amount": transfer.amount})


def wallet_detail(request, wallet_id):
    wallet = get_object_or_404(Wallet, pk=wallet_id)  # @hit
    return render(request, "wallet.html", {"wallet": wallet})


@api_view(["GET"])
def loan_detail(request, id):
    loan = Loan.objects.filter(id=id).first()  # @hit
    return Response(LoanSerializer(loan).data)


def account_by_query(request):
    account = Account.objects.get(pk=request.GET["id"])  # @hit
    return JsonResponse({"name": account.name})


def signed_in_is_not_owner(request, pk):
    if not request.user.is_authenticated:
        return JsonResponse({}, status=401)
    payout = Payout.objects.get(pk=pk)  # @hit
    return JsonResponse({"amount": payout.amount})


class TransferDetail(APIView):
    def get(self, request, pk):
        transfer = get_object_or_404(Transfer, id=pk)  # @hit
        return Response(TransferSerializer(transfer).data)


class WalletViewSet(ModelViewSet):
    queryset = Wallet.objects.all()  # @hit
    serializer_class = WalletSerializer


class InvoiceDetail(RetrieveAPIView):
    queryset = Invoice.objects.all()  # @hit
    serializer_class = InvoiceSerializer
