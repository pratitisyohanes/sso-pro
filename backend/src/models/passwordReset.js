// A password reset link sent by email. The link carries a random token; the table keeps only its hash
module.exports = (sequelize, DataTypes) => {
  const PasswordReset = sequelize.define(
    'PasswordReset',
    {
      id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
      userId: { type: DataTypes.UUID, allowNull: false },
      tokenHash: { type: DataTypes.STRING(64), allowNull: false, unique: true },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
      usedAt: { type: DataTypes.DATE },
      ip: { type: DataTypes.STRING(45) },
    },
    { tableName: 'password_resets', underscored: true, updatedAt: false },
  );

  return PasswordReset;
};
