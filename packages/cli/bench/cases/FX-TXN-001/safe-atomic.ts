export const debit = (id: string, amount: number) =>
  prisma.wallet.update({ where: { id }, data: { balance: { decrement: amount } } });
