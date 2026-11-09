export const Wallet = sequelize.define('wallet', {
  balance: DataTypes.FLOAT, // @hit
  amount: { type: DataTypes.DOUBLE }, // @hit
  rating: DataTypes.FLOAT,
  total: DataTypes.DECIMAL(14, 2),
});
