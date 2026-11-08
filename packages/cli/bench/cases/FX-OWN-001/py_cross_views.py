from .py_cross_services import get_wallet, get_scoped_wallet, get_checked_wallet
from . import py_cross_loans as loans
from .py_cross_accounts import AccountService


def wallet_view(request, pk):
    return JsonResponse(get_wallet(pk))  # @hit


def checked_wallet_view(request, pk):
    return JsonResponse(get_checked_wallet(pk))


def scoped_wallet_view(request, pk):
    return JsonResponse(get_scoped_wallet(request, pk))


def loan_view(request, pk):
    return JsonResponse(loans.load(pk))  # @hit


def loan_total_view(request, pk):
    return JsonResponse(loans.total(pk))


class AccountDetail(APIView):
    def get(self, request, pk):
        return Response(AccountService().by_id(pk))  # @hit


class OwnAccountDetail(APIView):
    def get(self, request, pk):
        return Response(AccountService().mine(pk))
