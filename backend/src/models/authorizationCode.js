module.exports = (sequelize, DataTypes) =>
  sequelize.define(
    'AuthorizationCode',
    {
      codeHash: { type: DataTypes.STRING(64), primaryKey: true },
      clientId: { type: DataTypes.STRING(50), allowNull: false },
      sessionId: { type: DataTypes.UUID, allowNull: false },
      userId: { type: DataTypes.UUID, allowNull: false },
      redirectUri: { type: DataTypes.STRING(255), allowNull: false },
      codeChallenge: { type: DataTypes.STRING(128), allowNull: false },
      nonce: { type: DataTypes.STRING(255) },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
      usedAt: { type: DataTypes.DATE },
    },
    { tableName: 'authorization_codes', underscored: true, updatedAt: false },
  );
