export async function getLoan(req: Request, res: Response) {
  const { rows } = await db.query('select * from loans where id = $1 and customer_id = $2', [req.params.id, req.user.id]);
  res.json(rows[0]);
}
