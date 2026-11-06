import { randomUUID } from 'node:crypto';
import { nanoid } from 'nanoid';

// Paystack transfers
export function references(id: string) {
  const reference = randomUUID();
  const txRef = `tx-${randomUUID()}`;
  const paymentReference = nanoid();
  const timed = `${Date.now()}-${randomUUID()}`;
  const startedAt = Date.now();
  const retryDelay = Math.random() * 100;
  const transferRef = id;
  const preference = Date.now();
  const orderRef = await lookUp(id);
  return { reference, txRef, paymentReference, timed, startedAt, retryDelay, transferRef, preference, orderRef };
}
