/*
 * The vocabulary the extractors and rules share. Names are compared in lower case without
 * separators, so `bvn_number` and `bvnNumber` are the same name.
 */

const normalize = (name: string) => name.replace(/[_-]/g, '').toLowerCase();

const KYC = new Set(['bvn', 'nin', 'bvnnumber', 'ninnumber', 'bankverificationnumber', 'nationalidnumber', 'nationalid']);
const OTP = new Set(['otp', 'otpcode', 'onetimepassword', 'passcode', 'verificationcode']);
export const isKycName = (name: string) => KYC.has(normalize(name));
export const isOtpName = (name: string) => OTP.has(normalize(name));

/** A name that says a value is masked: `maskBvn(x)`, `redact(x)`, `last4`. */
export const MASKING = /mask|redact|last_?4|last_?four/i;

/** A person or business that owns records. `walletId` names the record itself, so it's no owner check on its own. */
export const OWNER_NAME = /^(?:user|owner|customer|merchant|tenant|org|organi[sz]ation|company|business)_?id$/i;

/** A query field that limits records to their owner. */
export const OWNER_FIELD = /^(?:user|owner|customer|account|wallet|merchant|tenant|org|organi[sz]ation|company|business)_?id$/i;

export const MONEY = /transfer|wallet|account|payout|withdraw|deposit|transaction|payment|balance|loan|disburse|beneficiar|card|invoice|expense|income|ledger|savings|statement|receipt/i;

export const MONEY_OUT = /transfer|payout|withdraw|disburs|send[-_]?money/i;

/** Splits `generateOtpCode` or `generate_otp_code` into lower-case words. */
export const wordsOf = (text: string) =>
  text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);

const SECRET_WORD = new Set(['otp', 'pin', 'token', 'code', 'codes', 'passcode', 'verification']);
/** These codes aren't secrets. */
const HARMLESS_CODE = new Set(['referral', 'promo', 'coupon', 'discount', 'color', 'colour', 'zip', 'postal', 'country', 'currency', 'status', 'error', 'bank', 'qr', 'invite', 'product', 'sort']);

/** Whether the names around a random number say it's a secret code. */
export function namesSecretCode(context: string): boolean {
  const words = wordsOf(context);
  return words.some((w) => SECRET_WORD.has(w)) && !words.some((w) => HARMLESS_CODE.has(w));
}
