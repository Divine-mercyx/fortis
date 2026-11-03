// monnify transaction completion
router.post('/webhooks/monnify', express.raw({ type: '*/*' }), (req, res) => {
  if (!validateSignature(req.body, req.header('monnify-signature'))) return res.sendStatus(401);
  res.sendStatus(200);
});
