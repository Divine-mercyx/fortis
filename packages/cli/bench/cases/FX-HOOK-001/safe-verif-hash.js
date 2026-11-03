// flutterwave
router.post('/webhooks/flutterwave', (req, res) => {
  if (req.headers['verif-hash'] !== process.env.FLW_SECRET_HASH) return res.status(401).end();
  res.end();
});
