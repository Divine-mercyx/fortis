import { Router } from 'express';
export const router = Router();

router.post('/pin/reset', async (req, res) => { // @hit
  const row = await pinResets.findOne({ code: req.body.code });
  if (row.expiresAt < new Date()) return res.status(400).end();
  await wallets.update(row.userId, { pin: await hash(req.body.newPin) });
  res.json({ ok: true });
});
