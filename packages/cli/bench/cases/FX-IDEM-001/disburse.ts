router.post('/loans/:id/disburse', requireAdmin, async (req, res) => { // @hit
  await disburse(req.params.id);
  res.sendStatus(202);
});
