// A browser logged in to KandangID. stage stays MFA_* until the second factor passes; only ACTIVE counts as logged in
module.exports = (sequelize, DataTypes) => {
  const SsoSession = sequelize.define(
    'SsoSession',
    {
      id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
      sidHash: { type: DataTypes.STRING(64), allowNull: false, unique: true },
      userId: { type: DataTypes.UUID, allowNull: false },
      name: { type: DataTypes.STRING(100), allowNull: false },
      email: { type: DataTypes.STRING(150), allowNull: false },
      role: { type: DataTypes.ENUM('ADMIN', 'USER'), allowNull: false },
      stage: { type: DataTypes.ENUM('MFA_VERIFY', 'MFA_SETUP', 'ACTIVE'), allowNull: false },
      mfaAttempts: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
      userAgent: { type: DataTypes.STRING(255) },
      ip: { type: DataTypes.STRING(45) },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
      lastSeenAt: { type: DataTypes.DATE },
    },
    { tableName: 'sso_sessions', underscored: true },
  );

  SsoSession.prototype.isActive = function isActive() {
    return this.stage === 'ACTIVE' && this.expiresAt > new Date();
  };

  SsoSession.associate = (models) => {
    SsoSession.hasMany(models.RefreshToken, { foreignKey: 'sessionId', as: 'refreshTokens' });
  };

  return SsoSession;
};
