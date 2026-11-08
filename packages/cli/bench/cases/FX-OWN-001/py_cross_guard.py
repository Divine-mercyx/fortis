def assert_owns_wallet(wallet):
    if wallet.user_id != current_user.id:
        raise PermissionDenied
