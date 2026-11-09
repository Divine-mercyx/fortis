import Flutterwave from 'flutterwave-node-v3';

const flw = new Flutterwave(process.env.FLW_PUBLIC!, process.env.FLW_SECRET!);

router.post('/card', async (req, res) => {
  const result = await flw.Charge.card({ // @hit
    tx_ref: req.body.reference,
    amount: req.body.amount,
  });
  res.json(result);
});

router.post('/bank', async (req, res) => {
  const { amount } = req.body;
  const result = await flw.Charge.ng({ amount, tx_ref: req.body.reference }); // @hit
  res.json(result);
});
