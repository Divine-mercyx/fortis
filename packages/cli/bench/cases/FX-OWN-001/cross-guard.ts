export async function assertOwnsWallet(wallet: Wallet) {
  if (wallet.userId !== currentUser().id) throw new Error('not yours');
}
