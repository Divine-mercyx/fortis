router.get('/articles/:id', async (req, res) => {
  const article = await Article.findById(req.params.id);
  res.json(article);
});
