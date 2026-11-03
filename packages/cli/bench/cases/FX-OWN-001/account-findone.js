router.get('/accounts/:id/statement', async (req, res) => {
  const account = await Account.findOne({ id: req.params.id }); // @hit
  res.send(account.statement);
});
