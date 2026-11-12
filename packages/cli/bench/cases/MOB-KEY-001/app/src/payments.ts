import axios from 'axios';

const secret = process.env.EXPO_PUBLIC_PAYSTACK_SECRET_KEY; // @hit
const publicKey = process.env.EXPO_PUBLIC_PAYSTACK_PUBLIC_KEY;
const serviceRole = process.env.EXPO_PUBLIC_SUPABASE_SERVICE_ROLE_KEY; // @hit

export async function verify(reference: string) {
  return axios.get(`https://api.paystack.co/transaction/verify/${reference}`, { headers: { Authorization: `Bearer ${secret}` } });
}

export const label = 'Never put EXPO_PUBLIC_ in front of a SECRET_KEY';
