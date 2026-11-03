router.get('/transfers/:id', auth, async (req, res) => {
  const transfer = await Transfer.findOne({ _id: req.params.id, userId: req.user.id });
  res.json(transfer);
});
