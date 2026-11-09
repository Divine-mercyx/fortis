import axios from 'axios';

// Mono (open banking): the secret key goes in mono-sec-key
export const mono = axios.create({ baseURL: 'https://api.withmono.com', headers: { 'mono-sec-key': '{{MONO_LIVE}}' } }); // @hit
export const monoTest = new Mono({ secretKey: '{{MONO_TEST}}' }); // @hit

// Dojah (KYC): the secret key goes raw in Authorization, next to the AppId
export const dojah = { AppId: '64f0c1a2b3d4e5f60718293a', Authorization: '{{DOJAH_PROD}}' }; // @hit

// Africa's Talking (SMS, USSD, airtime)
export const at = AfricasTalking({ username: 'acme', apiKey: '{{AT_KEY}}' }); // @hit

// Near misses: Mono public keys ship to the browser; docs placeholders and env reads are not keys
export const monoWidget = { key: '{{MONO_PUBLIC}}' };
export const placeholder = { secretKey: 'live_sk_...', apiKey: 'atsk_your_actual_key_here' };
export const fromEnv = { secretKey: process.env.MONO_SECRET_KEY, apiKey: process.env.AT_API_KEY };
// Payment keys are FX-SEC-001's job, so this rule leaves them alone
export const kora = '{{KORAPAY_LIVE}}';
