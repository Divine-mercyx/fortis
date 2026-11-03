router.post('/loans/:id/finance-disbursement-override', async (req, res) => { // @hit
  await forceDisburse(req.params.id);
  res.json({ ok: true });
});
