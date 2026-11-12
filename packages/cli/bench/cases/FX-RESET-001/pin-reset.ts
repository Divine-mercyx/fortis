export async function resetTransactionPin(req, res) { // @hit
  const reset = await PinReset.findOne({ where: { code: req.body.code } });
  await Wallet.update({ pin: await bcrypt.hash(req.body.newPin, 12) }, { where: { userId: reset.userId } });
  return res.json({ ok: true });
}

export async function forgotTransactionPin(req, res) {
  const code = crypto.randomInt(100000, 999999).toString();
  await sms.send(req.user.phone, `Your PIN reset code is ${code}`);
  return res.json({ sent: true });
}
