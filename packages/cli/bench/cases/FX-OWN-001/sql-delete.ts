router.delete('/beneficiaries/:id', auth, async (req, res) => {
  await pool.query('delete from beneficiaries where id = $1', [req.params.id]); // @hit
  res.sendStatus(204);
});
