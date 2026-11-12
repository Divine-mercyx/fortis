import crypto from 'node:crypto';
import { Router } from 'express';
export const router = Router();

router.post('/password/forgot', async (req, res) => {
  const user = await users.findByEmail(req.body.email);
  if (user) {
    const token = crypto.randomBytes(32).toString('hex');
    await resets.create({ userId: user.id, hash: sha256(token), expiresAt: new Date(Date.now() + 30 * 60_000) });
    await mailer.send(user.email, `${config.appUrl}/reset?token=${token}`);
  }
  res.json({ message: 'If that account exists, we have sent a link.' });
});

router.post('/password/reset', async (req, res) => {
  const row = await resets.findOne({ hash: sha256(req.body.token) });
  if (!row || row.expiresAt < new Date()) return res.status(400).end();
  await users.update(row.userId, { password: await hash(req.body.newPassword) });
  await resets.deleteMany({ userId: row.userId });
  res.json({ ok: true });
});

export function resetFilters(state) {
  state.page = 1;
  state.seed = Math.random();
  return { code: state.seed };
}
