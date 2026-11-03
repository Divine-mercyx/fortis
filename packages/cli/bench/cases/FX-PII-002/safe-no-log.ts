export const payload = { bvn: input.bvn, dob: input.dob };
await dojah.post('/kyc/bvn', payload);
