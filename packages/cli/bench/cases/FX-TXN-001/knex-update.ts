const acct = await knex('accounts').where({ id }).first();
acct.balance = acct.balance - amount; // @hit
await knex('accounts').where({ id }).update({ balance: acct.balance });
