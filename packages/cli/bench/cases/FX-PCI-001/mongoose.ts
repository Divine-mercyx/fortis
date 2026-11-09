export const CardSchema = new Schema({
  cardNumber: String, // @hit
  cvv: { type: String }, // @hit
  last4: String,
  brand: { type: String },
});
