import { Wallet } from './models';

export async function debit(id: string, amount: number) {
  const wallet = await Wallet.findById(id);
  wallet.balance = wallet.balance - amount; // @hit
  await wallet.save();
}

export async function credit(id: string, amount: number) {
  const wallet = await Wallet.findById(id);
  wallet.balance += amount; // @hit
  await wallet.save();
}

export async function hold(id: string, amount: number) {
  const wallet = await Wallet.findById(id);
  wallet.availableBalance -= amount; // @hit
  wallet.ledgerBalance = Number(wallet.ledgerBalance) + amount; // @hit
  await wallet.save();
}

export const describeBalance = (wallet: { balance: number }) => `Balance: ${wallet.balance}`;
