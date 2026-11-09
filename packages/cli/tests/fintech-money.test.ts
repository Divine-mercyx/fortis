import { describe, expect, it } from 'vitest';

import { cardDataRule, clientAmountRule, isMoneyName, moneyFloatRule, predictableRefRule } from '../src/rules/fintech-money';
import { emptyContext, type FileRule } from '../src/rules/types';

const run = (rule: FileRule, path: string, text: string) => rule.run({ path, text, lines: text.split('\n') }, emptyContext()).map((d) => d.line);

describe('what counts as a money name', () => {
  it('goes by the last word', () => {
    for (const name of ['amount', 'totalAmount', 'unit_price', 'walletBalance', 'BALANCE', 'platformFee', 'amount_kobo']) expect(isMoneyName(name), name).toBe(true);
    for (const name of ['feedback', 'amount_label', 'fee_type', 'priceList', 'totally', 'rating', '']) expect(isMoneyName(name), name).toBe(false);
  });
});

describe('code nobody ships as money handling', () => {
  const bundle = `${'x'.repeat(600)} const reference = Date.now(); parseFloat(amount); logger.info(cvv); paystack.transaction.initialize({ amount: req.body.amount });`;

  it('skips minified lines in every rule', () => {
    for (const rule of [moneyFloatRule, cardDataRule, predictableRefRule, clientAmountRule]) expect(run(rule, 'src/payment.js', `// paystack payment\n${bundle}`), rule.id).toEqual([]);
  });

  it('skips money parsed in browser code and components', () => {
    for (const path of ['BTCPayServer/wwwroot/app.js', 'public/app.js', 'packages/desktop-client/src/a.ts', 'src/Price.tsx']) expect(run(moneyFloatRule, path, 'const a = parseFloat(amount);'), path).toEqual([]);
    expect(run(moneyFloatRule, 'src/ledger.ts', 'const a = parseFloat(amount);')).toEqual([1]);
  });

  it('honours an ignore comment in every rule', () => {
    expect(run(moneyFloatRule, 'src/a.ts', 'const a = parseFloat(amount); // fortis-ignore')).toEqual([]);
    expect(run(cardDataRule, 'src/a.ts', 'logger.info(cvv); // fortis-ignore')).toEqual([]);
    expect(run(predictableRefRule, 'src/payment.ts', 'const reference = Date.now(); // fortis-ignore')).toEqual([]);
    expect(run(clientAmountRule, 'src/a.ts', 'paystack.transaction.initialize({ amount: req.body.amount }); // fortis-ignore')).toEqual([]);
  });
});

describe('what fortis sees as the customer choosing the amount', () => {
  const call = 'paystack.transaction.initialize({ amount: req.body.amount });';

  it('skips top-ups, deposits and donations, by path or nearby code', () => {
    expect(run(clientAmountRule, 'src/routes/wallet-topup.ts', call)).toEqual([]);
    expect(run(clientAmountRule, 'src/donations.ts', call)).toEqual([]);
    expect(run(clientAmountRule, 'src/pay.ts', `router.post('/deposit', async (req, res) => {\n  ${call}\n});`)).toEqual([]);
    expect(run(clientAmountRule, 'src/pay.ts', `router.post('/checkout', async (req, res) => {\n  ${call}\n});`)).toEqual([2]);
  });

  it('needs a payment provider in the file', () => {
    expect(run(clientAmountRule, 'src/a.ts', 'db.create({ amount: req.body.amount });')).toEqual([]);
  });
});

describe('a card column that is encrypted', () => {
  it('is left alone', () => {
    expect(run(cardDataRule, 'src/m.py', 'card_number = EncryptedCharField()\ncvv = models.CharField(max_length=4)  # encrypted by the vault')).toEqual([]);
  });
});
