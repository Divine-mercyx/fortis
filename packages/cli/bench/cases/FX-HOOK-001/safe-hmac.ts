import { createHmac, timingSafeEqual } from 'node:crypto';
// paystack
app.post('/webhooks/paystack', (req, res) => {
  const hash = createHmac('sha512', process.env.PAYSTACK_SECRET_KEY!).update(req.rawBody).digest('hex');
  if (!timingSafeEqual(Buffer.from(hash), Buffer.from(String(req.headers['x-paystack-signature'])))) return res.sendStatus(401);
  res.sendStatus(200);
});
