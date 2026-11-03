// The ID flows through a service; a pattern check can't follow it (known miss).
router.get('/loans/:id', async (req, res) => {
  const id = req.params.id;
  const loan = await loanService.get(id); // @hit
  res.json(loan);
});
