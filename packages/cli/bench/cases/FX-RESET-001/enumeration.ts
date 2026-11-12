import { Router } from 'express';
export const router = Router();

router.post('/password/forgot', async (req, res) => {
  const user = await users.findByEmail(req.body.email);
  if (!user) return res.status(404).json({ error: 'User not found' }); // @hit
  await mailer.sendResetEmail(user);
  res.json({ ok: true });
});
