export function convert(amount: string, row: { amount: string }) {
  const isCredit = parseFloat(amount) < 0;
  const positive = Number.parseFloat(row.amount) >= 0;
  const kobo = Math.round(parseFloat(amount) * 100);
  return { isCredit, positive, kobo };
}
