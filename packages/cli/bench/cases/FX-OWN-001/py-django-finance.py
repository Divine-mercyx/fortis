def edit_expense(request, id):
    expense = Expense.objects.get(pk=id)  # @hit
    if request.method == "POST":
        expense.owner = request.user
        expense.save()
    return render(request, "edit.html", {"expense": expense})


def delete_income(request, id):
    income = UserIncome.objects.get(pk=id)  # @hit
    income.delete()
    return redirect("income")


def ledger_entry(request, pk):
    return Ledger.objects.get(pk=pk)  # @hit


def savings_goal(request, pk):
    return Savings.objects.get(pk=pk)  # @hit


def statement(request, pk):
    return Statement.objects.get(pk=pk)  # @hit
