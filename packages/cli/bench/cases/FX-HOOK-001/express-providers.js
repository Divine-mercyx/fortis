const express = require('express');
const { creditFromPaystack, creditFromFlutterwave, creditFromKora, creditFromOpay } = require('./credits');

const app = express();
app.post('/webhooks/paystack', async (req, res) => { // @hit
  await creditFromPaystack(req.body);
  res.sendStatus(200);
});
app.post('/webhook/flutterwave', async (req, res) => { // @hit
  await creditFromFlutterwave(req.body);
  res.sendStatus(200);
});
app.all('/kora/webhook', async (req, res) => { // @hit
  await creditFromKora(req.body);
  res.sendStatus(200);
});
app.post('/api/opay-webhook', async (req, res) => { // @hit
  await creditFromOpay(req.body);
  res.sendStatus(200);
});
app.get('/webhooks/paystack/health', (req, res) => res.sendStatus(200));
