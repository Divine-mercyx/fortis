export async function debit(walletId: string, amount: number) {
  const wallet = await Wallet.findById(walletId);
  wallet.balance = wallet.balance - amount; // @hit
  await wallet.save();
}
