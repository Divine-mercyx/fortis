import axios from 'axios';

// Paystack checkout
router.post('/pay', async (req, res) => {
  const { data } = await axios.post('https://api.paystack.co/transaction/initialize', { // @hit
    email: req.user.email,
    amount: req.body.amount,
  });
  res.json(data);
});
