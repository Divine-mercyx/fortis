import { monnify } from './monnify';
import { squad } from './squad';
import { korapay } from './korapay';

router.post('/pay', async (req, res) => {
  const result = await monnify.initialize({ amount: req.body.amount, customerEmail: req.user.email }); // @hit
  res.json(result);
});

router.post('/pay/squad', async (req, res) => {
  const { amount } = req.body;
  const result = await squad.initiate({ // @hit
    amount,
    email: req.user.email,
  });
  res.json(result);
});

router.post('/pay/kora', async (req, res) => {
  const result = await korapay.charge({ amount: req.body.price, currency: 'NGN' }); // @hit
  res.json(result);
});
