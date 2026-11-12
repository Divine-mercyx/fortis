import { Router } from 'express';
import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5 });
const otpLimiter = rateLimit({ windowMs: 60 * 1000, max: 3 });
export const router = Router();

router.post('/auth/login', loginLimiter, async (req, res) => {
  res.json(await auth.login(req.body.email, req.body.password));
});
router.post('/auth/otp/verify', otpLimiter, async (req, res) => {
  res.json(await auth.verifyOtp(req.body.phone, req.body.otp));
});
router.post('/wallet/pin/verify', async (req, res) => {
  const attempts = await pinAttempts.increment(req.user.id);
  if (attempts > 5) return res.status(423).json({ error: 'PIN locked' });
  res.json({ ok: await pins.check(req.user.id, req.body.pin) });
});
