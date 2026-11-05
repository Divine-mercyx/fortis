from django.contrib.admin.views.decorators import staff_member_required
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAdminUser
from rest_framework.viewsets import ModelViewSet


def scoped_in_query(request, pk):
    return Transfer.objects.get(pk=pk, owner=request.user)


def scoped_helper(request, pk):
    return get_object_or_404(Wallet, pk=pk, user=request.user)


def checked_after_loading(request, pk):
    transfer = Transfer.objects.get(pk=pk)
    if transfer.user != request.user:
        raise PermissionDenied
    return transfer


class WalletViewSet(ModelViewSet):
    queryset = Wallet.objects.all()

    def get_queryset(self):
        return Wallet.objects.filter(user=self.request.user)


class StaffLoanViewSet(ModelViewSet):
    permission_classes = [IsAdminUser]
    queryset = Loan.objects.all()


@staff_member_required
def admin_transfer(request, pk):
    return Transfer.objects.get(pk=pk)


@router.get("/wallets/{id}")
def read_wallet(id: int, db=Depends(get_db), current_user=Depends(get_current_user)):
    return db.query(Wallet).filter(Wallet.id == id, Wallet.user_id == current_user.id).first()


@bp.route("/transfers/<int:id>")
def transfer(id):
    return Transfer.query.filter_by(id=id, user_id=g.user.id).first_or_404()


def load_transfer(transfer_id):
    # Not a request handler. Whatever calls this is responsible for the check.
    return Transfer.objects.get(pk=transfer_id)


def constant_lookup(request):
    return Wallet.objects.get(pk=settings.FEES_WALLET_ID)


def not_money(request, pk):
    return Article.objects.get(pk=pk)
