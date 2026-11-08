import { getWallet, getScopedWallet, getCheckedWallet } from './cross-service';
import * as cards from './cross-cards';
import loanService from './cross-loans';
import { AccountsService } from './cross-accounts';

router.get('/wallets/:id', async (req, res) => {
  res.json(await getWallet(req.params.id)); // @hit
});

router.get('/wallets/:id/checked', async (req, res) => {
  res.json(await getCheckedWallet(req.params.id));
});

router.get('/wallets/:id/scoped', async (req, res) => {
  const id = req.params.id;
  res.json(await getScopedWallet(id));
});

router.get('/cards/:id', async (req, res) => {
  const { id } = req.params;
  res.json(await cards.load(id)); // @hit
});

router.get('/loans/:id', async (req, res) => {
  res.json(await loanService.find(req.params.id)); // @hit
});

router.get('/loans/:id/total', async (req, res) => {
  res.json(await loanService.total(req.params.id));
});

@Controller('accounts')
export class AccountsController {
  constructor(private readonly accounts: AccountsService) {}

  @Get(':id')
  one(@Param('id') id: string) {
    return this.accounts.byId(id); // @hit
  }

  @Get(':id/mine')
  mine(@Param('id') id: string) {
    return this.accounts.mine(id);
  }
}
