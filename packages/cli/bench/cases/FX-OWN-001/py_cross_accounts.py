class AccountService:
    def by_id(self, account_id):
        return Account.objects.get(pk=account_id)

    def mine(self, account_id):
        return Account.objects.get(pk=account_id, owner=current_user)
