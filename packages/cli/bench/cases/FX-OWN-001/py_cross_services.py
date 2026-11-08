from .py_cross_guard import assert_owns_wallet


def get_wallet(wallet_id):
    return _load(wallet_id)


def _load(wallet_id):
    return Wallet.objects.get(pk=wallet_id)


def get_checked_wallet(wallet_id):
    wallet = Wallet.objects.get(pk=wallet_id)
    assert_owns_wallet(wallet)
    return wallet


def get_scoped_wallet(request, wallet_id):
    return Wallet.objects.get(pk=wallet_id, user=request.user)
