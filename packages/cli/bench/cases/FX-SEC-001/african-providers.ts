export const seerbit = { secret: '{{SEERBIT_LIVE}}', publicKey: process.env.SEERBIT_PUBLIC }; // @hit
export const seerbitTest = '{{SEERBIT_TEST}}'; // @hit
export const opayPrivate = '{{OPAY_PRIVATE}}'; // @hit
export const squad = new Squad('{{SQUAD_SANDBOX}}'); // @hit
export const kora = axios.create({ headers: { Authorization: 'Bearer {{KORAPAY_LIVE}}' } }); // @hit
export const budpay = { secretKey: '{{BUDPAY_TEST}}' }; // @hit

// Public keys are meant to ship to the browser
export const seerbitPublic = '{{SEERBIT_PUBLIC}}';
export const opayPublic = '{{OPAY_PUBLIC}}';
// Mono, Dojah and Africa's Talking keys belong to SEC-GEN-001, not the payment-key rule
export const mono = '{{MONO_LIVE}}';
export const dojah = '{{DOJAH_PROD}}';
