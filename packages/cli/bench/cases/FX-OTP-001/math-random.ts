export function generateOtp() {
  const otp = Math.floor(100000 + Math.random() * 900000); // @hit
  return String(otp);
}
