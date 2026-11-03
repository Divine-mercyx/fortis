// Projected balance for a UI chart, nothing is saved
let balance = opening;
for (const t of txns) balance = balance + t.amount;
