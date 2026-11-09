// Paystack transfers
export function references(id: string) {
  const reference = `TX-${Date.now()}`; // @hit
  const txRef = 'FLW-' + Math.random().toString(36).slice(2); // @hit
  const paymentReference = `pay_${new Date().getTime()}`; // @hit
  const transferRef = Math.floor(Math.random() * 1e9); // @hit
  const orderRef = +new Date() + id; // @hit
  return {
    tx_ref: Date.now(), // @hit
    reference: `trx_${Math.random()}`, // @hit
    merchantRef: `${id}-${Date.now()}`, // @hit
  };
}
