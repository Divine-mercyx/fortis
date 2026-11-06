import { Router } from 'express';

import { settleMonnify, settleInterswitch } from './settlement';

export const router = Router();
// Monnify calls this when a transfer settles.
router.post('/monnify/webhook', async (req, res) => { // @hit
  await settleMonnify(req.body.eventData);
  res.status(200).end();
});
router.post('/webhook/interswitch', async (req, res) => { // @hit
  await settleInterswitch(req.body);
  res.status(200).end();
});
router.use('/webhooks/remita', remitaHandler); // @hit
