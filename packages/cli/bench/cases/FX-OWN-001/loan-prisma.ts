app.get('/loans/:loanId', async (req, res) => {
  const loan = await prisma.loan.findUnique({ where: { id: req.params.loanId } }); // @hit
  return res.json(loan);
});
