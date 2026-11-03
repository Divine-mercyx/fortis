router.get('/transfers/:id', auth, async (req, res) => {
  const transfer = await Transfer.findById(req.params.id); // @hit
  res.json(transfer);
});
