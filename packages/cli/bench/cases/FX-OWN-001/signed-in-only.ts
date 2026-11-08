// Being signed in isn't owning the record.
router.get('/wallets/:id', async (req, res) => {
  if (!req.user) return res.sendStatus(401);
  const wallet = await Wallet.findById(req.params.id); // @hit
  res.json(wallet);
});

router.get('/accounts/:accountId', async (req, res) => {
  const { accountId } = req.params;
  res.json(await Account.findById(accountId)); // @hit
});

router.get('/accounts/:accountId/mine', async (req, res) => {
  const { accountId } = req.params;
  res.json(await Account.findOne({ _id: accountId, ownerId: req.user.id }));
});

router.get('/payments/:id', async (req, res) => {
  res.json(await paymentService.get(req.params.id, req.user.id));
});

router.get('/cache/:id', async (req, res) => {
  res.json(await walletCache.get(req.params.id));
});

export const rates = () => axios.get(`/wallets/${walletId}`);
