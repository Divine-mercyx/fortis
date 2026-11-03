// Back-office: staff with the loans:read permission may view any loan
adminRouter.get('/loans/:id', requirePermission('loans:read'), async (req, res) => {
  const loan = await Loan.findById(req.params.id); // fortis-ignore: staff-only route
  res.json(loan);
});
