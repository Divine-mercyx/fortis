async function credit(account, amount) {
  account.availableBalance += amount; // @hit
  await account.save();
}
