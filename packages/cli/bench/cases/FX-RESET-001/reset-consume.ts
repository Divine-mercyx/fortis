import { Router } from 'express';
export const router = Router();

router.post('/password/reset', async (req, res) => { // @hit
  const row = await resets.findOne({ token: req.body.token });
  await users.update(row.userId, { password: await hash(req.body.newPassword) });
  res.json({ ok: true });
});
