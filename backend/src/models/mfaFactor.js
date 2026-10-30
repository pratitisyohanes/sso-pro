// secret is AES-256-GCM ciphertext; it is pending (enabled = false) until the first valid code
module.exports = (sequelize, DataTypes) =>
  sequelize.define(
    'MfaFactor',
    {
      userId: { type: DataTypes.UUID, primaryKey: true },
      secret: { type: DataTypes.TEXT, allowNull: false },
      enabled: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
      lastStep: { type: DataTypes.BIGINT },
      setupAt: { type: DataTypes.DATE },
    },
    { tableName: 'mfa_factors', underscored: true },
  );
