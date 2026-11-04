from django.db.models import F


def locked_row(wallet_id, amount):
    with transaction.atomic():
        wallet = Wallet.objects.select_for_update().get(pk=wallet_id)
        wallet.balance -= amount
        wallet.save()


def atomic_update(wallet_id, amount):
    Wallet.objects.filter(pk=wallet_id).update(balance=F("balance") - amount)


def f_expression(wallet, amount):
    wallet.balance = F("balance") - amount
    wallet.save()


def sqlalchemy_lock(session, wallet_id, amount):
    wallet = session.query(Wallet).with_for_update().get(wallet_id)
    wallet.balance -= amount
    session.commit()


def raw_lock(cur, row, amount):
    cur.execute("SELECT balance FROM wallets WHERE id = %s FOR UPDATE", (row.id,))
    row.balance -= amount
    cur.execute("UPDATE wallets SET balance = %s", (row.balance,))


def display_only(statement):
    running_balance = 0
    for line in statement:
        running_balance += line.amount
    return running_balance


def in_memory(account, amount):
    account.balance -= amount
    return account


def comparison(wallet, conn):
    if wallet.balance == wallet.balance - 0:
        conn.commit()


def comment_only(session):
    # wallet.balance -= amount is what we used to do
    session.commit()
