export function other(req: Request) {
  const lat = parseFloat(req.body.latitude);
  const lng = parseFloat(req.body.longitude);
  const percent = parseFloat(req.body.discountPercent);
  const rating = parseFloat(review.rating);
  const version = parseFloat(process.versions.node);
  const feedback = parseFloat(form.feedback);
  const amountLabel = parseFloat(form.amount_label);
  const kobo = BigInt(req.body.amount);
  return { lat, lng, percent, rating, version, feedback, amountLabel, kobo };
}
