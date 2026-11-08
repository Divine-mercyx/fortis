import { assertOwnsWallet } from './cross-guard';

// Services the routes in cross-route.ts call: whether a route is safe depends on what these do.
export async function getWallet(id: string) {
  return loadWallet(id);
}

async function loadWallet(walletId: string) {
  return Wallet.findById(walletId);
}

export async function getCheckedWallet(id: string) {
  const wallet = await Wallet.findById(id);
  await assertOwnsWallet(wallet);
  return wallet;
}

export async function getScopedWallet(id: string) {
  return Wallet.findOne({ _id: id, userId: currentUser().id });
}
