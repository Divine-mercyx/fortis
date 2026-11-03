router.post('/transfers', auth, async (req, res) => { // @hit
  const t = await payments.send(req.user.id, req.body);
  res.status(201).json(t);
});
