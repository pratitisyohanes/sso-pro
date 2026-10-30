// Browser apps (booking-web, pos-web) are public OIDC clients: no secret, but fixed return addresses
module.exports = {
  async up(queryInterface, Sequelize) {
    const urls = { type: Sequelize.ARRAY(Sequelize.STRING(255)), allowNull: false, defaultValue: [] };
    await queryInterface.changeColumn('clients', 'secret_hash', { type: Sequelize.TEXT, allowNull: true });
    await queryInterface.addColumn('clients', 'redirect_uris', urls);
    await queryInterface.addColumn('clients', 'post_logout_redirect_uris', urls);
    await queryInterface.addColumn('clients', 'allowed_origins', urls);
    // Logins on the KandangID page may come without a known application
    await queryInterface.changeColumn('auth_events', 'client_id', { type: Sequelize.STRING(50), allowNull: true });
  },

  async down(queryInterface, Sequelize) {
    await queryInterface.removeColumn('clients', 'allowed_origins');
    await queryInterface.removeColumn('clients', 'post_logout_redirect_uris');
    await queryInterface.removeColumn('clients', 'redirect_uris');
    await queryInterface.sequelize.query('DELETE FROM auth_events WHERE client_id IS NULL');
    await queryInterface.changeColumn('auth_events', 'client_id', { type: Sequelize.STRING(50), allowNull: false });
    await queryInterface.sequelize.query('DELETE FROM clients WHERE secret_hash IS NULL');
    await queryInterface.changeColumn('clients', 'secret_hash', { type: Sequelize.TEXT, allowNull: false });
  },
};
