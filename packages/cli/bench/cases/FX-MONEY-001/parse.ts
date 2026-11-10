export function charge(req: Request) {
  const amount = parseFloat(req.body.amount); // @hit
  const fee = Number.parseFloat(req.body.fee); // @hit
  const total = parseFloat(order.total); // @hit
  const unitPrice = parseFloat(item.unit_price); // @hit
  const walletBalance = parseFloat(wallet.balance); // @hit
  return { amount, fee, total, unitPrice, walletBalance };
}
