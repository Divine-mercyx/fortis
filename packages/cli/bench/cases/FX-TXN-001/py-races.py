from django.db import transaction


def debit_django(wallet, amount):
    wallet.balance -= amount  # @hit
    wallet.save()


def credit_django(wallet, amount):
    wallet.balance = wallet.balance + amount  # @hit
    wallet.save(update_fields=["balance"])


def atomic_is_not_a_lock(wallet_id, amount):
    with transaction.atomic():
        wallet = Wallet.objects.get(pk=wallet_id)
        wallet.available_balance -= amount  # @hit
        wallet.save()


def debit_sqlalchemy(session, wallet, amount):
    wallet.balance -= amount  # @hit
    session.commit()


def credit_flask(wallet, amount):
    wallet.balance += amount  # @hit
    db.session.commit()


async def debit_async(session, wallet, amount):
    wallet.balance = wallet.balance - amount  # @hit
    await session.flush()


class Account:
    def withdraw(self, amount):
        self.balance -= amount  # @hit
        self.save()


def debit_sql(cur, row, amount):
    new_balance = 0
    row.balance -= amount  # @hit
    cur.execute("UPDATE wallets SET balance = %s", (row.balance,))
