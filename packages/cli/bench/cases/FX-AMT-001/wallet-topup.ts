import { paystack } from './paystack';

// Choosing how much to add is the point of a top-up.
router.post('/wallet/top-up', async (req, res) => {
  const tx = await paystack.transaction.initialize({ email: req.user.email, amount: req.body.amount });
  res.json(tx);
});
