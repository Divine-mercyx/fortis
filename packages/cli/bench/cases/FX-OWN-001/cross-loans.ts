export default {
  find(id: string) {
    return Loan.findById(id);
  },
  total(id: string) {
    return loanTotals[id];
  },
};
