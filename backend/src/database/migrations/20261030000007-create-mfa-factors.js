// TOTP secret per LDAP user; moved here from booking_db because the login page now lives in KandangID
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('mfa_factors', {
      user_id: { type: Sequelize.UUID, primaryKey: true, allowNull: false },
      secret: { type: Sequelize.TEXT, allowNull: false },
      enabled: { type: Sequelize.BOOLEAN, allowNull: false, defaultValue: false },
      last_step: { type: Sequelize.BIGINT },
      setup_at: { type: Sequelize.DATE },
      created_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.fn('NOW') },
      updated_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.fn('NOW') },
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('mfa_factors');
  },
};
