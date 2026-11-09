import { Router } from 'express';

import { send, payOut, withdraw, disburse } from './money';

const router = Router();
router.post('/transfers', async (req, res) => res.json(await send(req.body))); // @hit
router.post('/wallets/:id/transfer', async (req, res) => res.json(await send(req.body))); // @hit
router.put('/payouts/:id', async (req, res) => res.json(await payOut(req.body))); // @hit
router.post('/withdrawals', async (req, res) => res.json(await withdraw(req.body))); // @hit
router.post('/loans/disbursements', requireAdmin, async (req, res) => res.json(await disburse(req.body))); // @hit
router.post('/send-money', async (req, res) => res.json(await send(req.body))); // @hit
router.post('/v2/sendMoney', async (req, res) => res.json(await send(req.body))); // @hit

// Read-only, or nothing to do with moving money.
router.post('/transfers/quote', async (req, res) => res.json({ fee: 10 }));
router.post('/payouts/name-enquiry', async (req, res) => res.json({ name: 'A' }));
router.post('/profile', async (req, res) => res.json({}));
router.get('/transfers', async (req, res) => res.json([]));
