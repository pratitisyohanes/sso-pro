// Audit trail of every login check and account change, like the login history table in ERM
module.exports = (sequelize, DataTypes) => {
  const AuthEvent = sequelize.define(
    'AuthEvent',
    {
      id: { type: DataTypes.BIGINT, primaryKey: true, autoIncrement: true },
      // Null when someone logs in directly on the KandangID page without an application
      clientId: { type: DataTypes.STRING(50) },
      action: { type: DataTypes.STRING(30), allowNull: false },
      result: { type: DataTypes.STRING(30), allowNull: false },
      username: { type: DataTypes.STRING(150) },
      userId: { type: DataTypes.UUID },
      ip: { type: DataTypes.STRING(45) },
    },
    { tableName: 'auth_events', underscored: true, updatedAt: false },
  );

  AuthEvent.associate = (models) => {
    AuthEvent.belongsTo(models.Client, { foreignKey: 'clientId', as: 'client' });
  };

  return AuthEvent;
};
