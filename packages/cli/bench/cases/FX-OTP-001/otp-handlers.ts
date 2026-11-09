import { logger } from './logger';
import { randomInt } from 'node:crypto';

// otp for phone login
export const makeOtp = () => Math.floor(100000 + Math.random() * 900000); // @hit
export const verificationCode = String(Math.random()).slice(2, 8); // @hit

export function send(res: Response, phone: string, otp: string) {
  logger.debug('sending otp', otp); // @hit
  console.log(`otp for ${phone}: ${otp}`); // @hit
  res.json({ sent: true, otp }); // @hit
}

// None of these expose or weaken an OTP.
export const safeOtp = () => randomInt(100000, 999999);
export const notice = () => logger.info('OTP sent');
export const later = (res: Response) => res.json({ sent: true });
