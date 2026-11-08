def load(loan_id):
    return Loan.objects.get(pk=loan_id)


def total(loan_id):
    return TOTALS[loan_id]
