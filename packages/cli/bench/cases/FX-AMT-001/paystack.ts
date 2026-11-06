import { paystack } from './paystack';

router.post('/checkout', async (req, res) => {
  const tx = await paystack.transaction.initialize({ // @hit
    email: req.user.email,
    amount: req.body.amount,
  });
  res.json(tx);
});

router.post('/orders/pay', async (req, res) => {
  const { amount, email } = req.body;
  const tx = await paystack.transaction.initialize({ email, amount }); // @hit
  res.json(tx);
});

router.post('/invoices/pay', async (req, res) => {
  const amount = req.body.amount;
  const tx = await paystack.transaction.initialize({ // @hit
    email: req.user.email,
    amount: amount * 100,
  });
  res.json(tx);
});
