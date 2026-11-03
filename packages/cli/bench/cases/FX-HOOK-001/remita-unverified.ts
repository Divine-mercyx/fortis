// Remita payment notification
app.post('/remita/webhook', async (req, res) => { // @hit
  await settle(req.body.rrr);
  res.json({ ok: true });
});
