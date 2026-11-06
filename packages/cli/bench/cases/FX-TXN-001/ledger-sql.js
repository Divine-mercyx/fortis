const { pool } = require('./db');

async function withdraw(accountId, amount) {
  const { rows } = await pool.query('select * from accounts where id = $1', [accountId]);
  const account = rows[0];
  account.balance = account.balance - amount; // @hit
  await pool.query('update accounts set balance = $1 where id = $2', [account.balance, accountId]);
}

async function deposit(accountId, amount) {
  const { rows } = await pool.query('select * from accounts where id = $1', [accountId]);
  let balance = rows[0].balance;
  balance += amount; // @hit
  await pool.query('update accounts set balance = $1 where id = $2', [balance, accountId]);
}

async function reverse(accountId, amount) {
  const { rows } = await pool.query('select * from accounts where id = $1', [accountId]);
  const totalBalance = rows[0].total_balance;
  const merchant = rows[0];
  merchant.settlementBalance -= amount; // @hit
  merchant.pendingBalance = merchant.pendingBalance + amount; // @hit
  await pool.query('update accounts set settlement_balance = $1, pending_balance = $2 where id = $3', [merchant.settlementBalance, merchant.pendingBalance, accountId]);
  return totalBalance;
}

module.exports = { withdraw, deposit, reverse };
