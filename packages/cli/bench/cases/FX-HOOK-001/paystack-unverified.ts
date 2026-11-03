// Paystack sends charge.success here
app.post('/webhooks/paystack', async (req, res) => { // @hit
  await creditWallet(req.body.data.reference);
  res.sendStatus(200);
});
