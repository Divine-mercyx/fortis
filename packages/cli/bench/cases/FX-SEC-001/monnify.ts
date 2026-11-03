const MONNIFY_API_KEY = '{{MONNIFY_PROD}}'; // @hit
export const monnifyAuth = Buffer.from(`${MONNIFY_API_KEY}:${process.env.MONNIFY_SECRET}`).toString('base64');
