const flutterwave = require('./flutterwave');
router.post('/flutterwave/webhook', async (req, res) => { // @hit
  if (req.body.event === 'charge.completed') await markPaid(req.body.data.tx_ref);
  res.end();
});
