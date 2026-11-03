export async function verify(bvn: string) {
  console.log('verifying', bvn); // @hit
  return dojah.lookupBvn(bvn);
}
