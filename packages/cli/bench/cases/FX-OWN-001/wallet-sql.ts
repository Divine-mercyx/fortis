export async function getWallet(req: Request, res: Response) {
  const { rows } = await db.query('select * from wallets where id = $1', [req.params.id]); // @hit
  res.json(rows[0]);
}
