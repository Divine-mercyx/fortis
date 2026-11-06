const stripe = require('stripe')(process.env.STRIPE_KEY);

app.post('/donations', async (req, res) => {
  const intent = await stripe.paymentIntents.create({ amount: req.body.amount, currency: 'ngn' });
  res.json(intent);
});
