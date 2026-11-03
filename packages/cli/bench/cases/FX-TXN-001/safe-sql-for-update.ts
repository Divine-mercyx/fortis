await client.query('BEGIN');
const { rows } = await client.query('select balance from wallets where id = $1 for update', [id]);
const balance = rows[0].balance - amount;
await client.query('update wallets set balance = $1 where id = $2', [balance, id]);
await client.query('COMMIT');
