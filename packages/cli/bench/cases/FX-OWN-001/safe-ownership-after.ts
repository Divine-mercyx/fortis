router.get('/wallets/:id', auth, async (req, res) => {
  const wallet = await Wallet.findById(req.params.id);
  if (!wallet || wallet.ownerId !== req.user.id) return res.sendStatus(404);
  res.json(wallet);
});
