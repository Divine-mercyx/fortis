import { Router } from 'express';
import { auth } from './auth.service';

export const router = Router();

router.post('/auth/login', async (req, res) => { // @hit
  res.json(await auth.login(req.body.email, req.body.password));
});

router.post('/auth/sign-in/phone', async (req, res) => { // @hit
  res.json(await auth.loginWithPhone(req.body.phone, req.body.password));
});

router.post('/auth/otp/verify', async (req, res) => { // @hit
  res.json(await auth.verifyOtp(req.body.phone, req.body.otp));
});

router.post('/auth/2fa', async (req, res) => { // @hit
  res.json(await auth.verifyTotp(req.user.id, req.body.code));
});

router.post('/auth/logout', async (req, res) => {
  await auth.logout(req.user.id);
  res.status(204).end();
});

router.get('/auth/login', (req, res) => res.render('login'));
