// Monnify payments
function build(id) {
  const trxRef = 'TRX' + Date.now(); // @hit
  const paymentRef = Date.now().toString(); // @hit
  const reference = id + Math.floor(Math.random() * 1000); // @hit
  const body = {
    transactionReference: new Date().getTime(), // @hit
    payment_reference: `P-${Date.now()}`, // @hit
  };
  return { trxRef, paymentRef, reference, body };
}
