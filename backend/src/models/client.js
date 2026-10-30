// An application allowed to use KandangID: a server with a secret (booking-api) or a browser app with return addresses (booking-web)
module.exports = (sequelize, DataTypes) => {
  const urls = { type: DataTypes.ARRAY(DataTypes.STRING(255)), allowNull: false, defaultValue: [] };

  const Client = sequelize.define(
    'Client',
    {
      id: { type: DataTypes.STRING(50), primaryKey: true },
      name: { type: DataTypes.STRING(100), allowNull: false },
      // Null for public browser clients, which prove themselves with PKCE instead
      secretHash: { type: DataTypes.TEXT },
      scopes: { type: DataTypes.ARRAY(DataTypes.STRING(30)), allowNull: false, defaultValue: [] },
      redirectUris: urls,
      postLogoutRedirectUris: urls,
      allowedOrigins: urls,
      isActive: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: true },
    },
    {
      tableName: 'clients',
      underscored: true,
      defaultScope: { attributes: { exclude: ['secretHash'] } },
      scopes: { withSecret: {} },
    },
  );

  Client.associate = (models) => {
    Client.hasMany(models.AuthEvent, { foreignKey: 'clientId', as: 'events' });
  };

  return Client;
};
