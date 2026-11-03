router.post('/otp/send', async (req, res) => {
  const otp = await issueOtp(req.body.phone);
  res.json({ sent: true, otp }); // @hit
});
