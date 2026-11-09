const stripe = require('stripe')(process.env.STRIPE_KEY);

app.post('/create-payment-intent', async (req, res) => {
  const intent = await stripe.paymentIntents.create({ // @hit
    amount: req.body.amount,
    currency: 'ngn',
  });
  res.json(intent);
});

app.post('/charge', async (req, res) => {
  const charge = await stripe.charges.create({ amount: Number(req.body.total), currency: 'ngn', source: req.body.token }); // @hit
  res.json(charge);
});

app.post('/session', async (req, res) => {
  const session = await stripe.checkout.sessions.create({ // @hit
    amount: req.query.amount,
  });
  res.json(session);
});
