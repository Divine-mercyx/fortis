app.post('/webhooks/github', async (req, res) => {
  await deploy(req.body);
  res.sendStatus(204);
});
