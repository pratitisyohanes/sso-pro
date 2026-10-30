// One row per browser that logged in to KandangID; the cookie holds a random id, the table only its hash
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('sso_sessions', {
      id: { type: Sequelize.UUID, primaryKey: true, allowNull: false },
      sid_hash: { type: Sequelize.STRING(64), allowNull: false, unique: true },
      user_id: { type: Sequelize.UUID, allowNull: false },
      name: { type: Sequelize.STRING(100), allowNull: false },
      email: { type: Sequelize.STRING(150), allowNull: false },
      role: { type: Sequelize.ENUM('ADMIN', 'USER'), allowNull: false },
      stage: { type: Sequelize.ENUM('MFA_VERIFY', 'MFA_SETUP', 'ACTIVE'), allowNull: false },
      mfa_attempts: { type: Sequelize.INTEGER, allowNull: false, defaultValue: 0 },
      user_agent: { type: Sequelize.STRING(255) },
      ip: { type: Sequelize.STRING(45) },
      expires_at: { type: Sequelize.DATE, allowNull: false },
      last_seen_at: { type: Sequelize.DATE },
      created_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.fn('NOW') },
      updated_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.fn('NOW') },
    });
    await queryInterface.addIndex('sso_sessions', ['user_id']);
    await queryInterface.addIndex('sso_sessions', ['expires_at']);
  },

  async down(queryInterface) {
    await queryInterface.dropTable('sso_sessions');
    await queryInterface.sequelize.query('DROP TYPE IF EXISTS "enum_sso_sessions_role";');
    await queryInterface.sequelize.query('DROP TYPE IF EXISTS "enum_sso_sessions_stage";');
  },
};
