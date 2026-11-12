import express from 'express';
const app = express();

app.post('/wallet/pin/verify', requireUser, verifyPin); // @hit
app.post('/wallet/transaction-pin/validate', requireUser, async (req, res) => { // @hit
  res.json({ ok: await pins.check(req.user.id, req.body.pin) });
});
app.put('/wallet/pin', requireUser, async (req, res) => { // @hit
  res.json(await pins.change(req.user.id, req.body.oldPin, req.body.newPin));
});
app.post('/transfers', requireUser, async (req, res) => {
  res.json(await transfers.create(req.user.id, req.body));
});
app.get('/wallet/pin/policy', (req, res) => res.json({ length: 4 }));

async function verifyPin(req, res) {
  res.json({ ok: await pins.check(req.user.id, req.body.pin) });
}
