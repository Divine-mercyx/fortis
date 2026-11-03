router.post('/transfers', auth, async (req, res) => {
  const key = req.header('Idempotency-Key');
  if (!key) return res.status(400).json({ error: 'Idempotency-Key required' });
  res.json(await payments.send(req.user.id, req.body, key));
});
