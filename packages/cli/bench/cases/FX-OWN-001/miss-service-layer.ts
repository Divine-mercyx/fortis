// The ID goes through a local and into a service nobody can read here, so it's judged by its name.
router.get('/loans/:id', async (req, res) => {
  const id = req.params.id;
  const loan = await loanService.get(id); // @hit
  res.json(loan);
});
