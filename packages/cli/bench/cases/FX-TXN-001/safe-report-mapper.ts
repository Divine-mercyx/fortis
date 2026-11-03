// From a real codebase: building a credit-report summary in memory (Map.set is not a database write)
const buckets = new Map<string, { balance: number }>();
for (const row of rows) {
  const bucket = buckets.get(row.type) ?? { balance: 0 };
  bucket.balance += parseAmount(row.CurrentBalanceAmt);
  buckets.set(row.type, bucket);
}
