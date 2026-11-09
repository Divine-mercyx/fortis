import Fastify from 'fastify';

import { markPaid } from './orders';

const app = Fastify();
// Paystack events
app.post('/payments/webhook', async (request) => { // @hit
  await markPaid((request.body as { data: { reference: string } }).data.reference);
  return { ok: true };
});
app.post('/billing/webhook', async (request) => { // @hit
  await markPaid((request.body as { reference: string }).reference);
  return { ok: true };
});
