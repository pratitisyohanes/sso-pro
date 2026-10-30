module.exports = (sequelize, DataTypes) => {
  const RefreshToken = sequelize.define(
    'RefreshToken',
    {
      id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
      tokenHash: { type: DataTypes.STRING(64), allowNull: false, unique: true },
      sessionId: { type: DataTypes.UUID, allowNull: false },
      clientId: { type: DataTypes.STRING(50), allowNull: false },
      userId: { type: DataTypes.UUID, allowNull: false },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
      revokedAt: { type: DataTypes.DATE },
    },
    { tableName: 'refresh_tokens', underscored: true, updatedAt: false },
  );

  RefreshToken.associate = (models) => {
    RefreshToken.belongsTo(models.SsoSession, { foreignKey: 'sessionId', as: 'session' });
  };

  return RefreshToken;
};
