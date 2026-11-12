import { Router } from 'express';
export const router = Router();

router.post('/password/forgot', async (req, res) => {
  const user = await users.findByEmail(req.body.email);
  const code = Math.floor(100000 + Math.random() * 900000); // @hit
  const link = `https://${req.headers.host}/reset?code=${code}`; // @hit
  logger.info({ code }); // @hit
  await mailer.send(user.email, link);
  res.json({ ok: true, code }); // @hit
});
