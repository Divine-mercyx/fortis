import { paystack } from './paystack';

router.post('/checkout', async (req, res) => {
  const order = await Order.findById(req.body.orderId);
  const tx = await paystack.transaction.initialize({ email: req.user.email, amount: order.total });
  res.json(tx);
});

router.post('/plans/subscribe', async (req, res) => {
  const plan = PLANS[req.body.plan];
  const tx = await paystack.transaction.initialize({ email: req.user.email, amount: plan.price });
  res.json(tx);
});

router.post('/verify', async (req, res) => {
  const amount = req.body.amount;
  await paystack.transaction.verify(req.body.reference);
  res.json({ amount });
});

router.get('/quote', async (req, res) => res.json({ amount: req.query.amount }));
