import { verifySignature } from '../lib/paystack';
app.post('/paystack/webhook', verifySignature, handlePaystackEvent);
