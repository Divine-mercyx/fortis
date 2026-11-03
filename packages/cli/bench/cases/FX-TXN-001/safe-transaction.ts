export async function debit(walletId: string, amount: number) {
  await prisma.$transaction(async (tx) => {
    const w = await tx.wallet.findUniqueOrThrow({ where: { id: walletId } });
    w.balance = w.balance - amount;
    await tx.wallet.update({ where: { id: walletId }, data: { balance: w.balance } });
  });
}
