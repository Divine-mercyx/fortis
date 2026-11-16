import axios from 'axios';

// Mono (open banking): the secret key goes in mono-sec-key
export const mono = axios.create({ baseURL: 'https://api.withmono.com', headers: { 'mono-sec-key': '{{MONO_LIVE}}' } }); // @hit
export const monoTest = new Mono({ secretKey: '{{MONO_TEST}}' }); // @hit

// Dojah (KYC): the secret key goes raw in Authorization, next to the AppId
export const dojah = { AppId: '64f0c1a2b3d4e5f60718293a', Authorization: '{{DOJAH_PROD}}' }; // @hit

// Africa's Talking (SMS, USSD, airtime)
export const at = AfricasTalking({ username: 'acme', apiKey: '{{AT_KEY}}' }); // @hit

// Infobip (SMS, WhatsApp): named from its shape, 32 hex characters, a dash and a UUID
export const infobip = { baseUrl: 'https://xyz12.api.infobip.com', auth: 'App {{INFOBIP_KEY}}' }; // @hit

// Providers that publish no key format, named from the setting the key is assigned to
export const TERMII_API_KEY = '{{GENERIC}}'; // @hit
export const smileIdConfig = { partnerId: '1234', smileIdApiKey: '{{GENERIC}}' }; // @hit
export const YOUVERIFY_TOKEN = '{{GENERIC}}'; // @hit
export const SUDO_API_KEY = '{{GENERIC}}'; // @hit

// Near misses: Mono public keys ship to the browser; docs placeholders and env reads are not keys
export const monoWidget = { key: '{{MONO_PUBLIC}}' };
export const placeholder = { secretKey: 'live_sk_...', apiKey: 'atsk_your_actual_key_here' };
export const fromEnv = { secretKey: process.env.MONO_SECRET_KEY, apiKey: process.env.AT_API_KEY };
export const termiiFromEnv = { apiKey: process.env.TERMII_API_KEY, prembly: process.env.PREMBLY_SECRET_KEY };
export const termiiDocs = { TERMII_API_KEY: 'your_termii_api_key' };
// Payment keys are FX-SEC-001's job, so this rule leaves them alone
export const kora = '{{KORAPAY_LIVE}}';
