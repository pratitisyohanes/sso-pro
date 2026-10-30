// One-time codes from /oidc/authorize, exchanged once at /oidc/token within 60 seconds
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('authorization_codes', {
      code_hash: { type: Sequelize.STRING(64), primaryKey: true, allowNull: false },
      client_id: { type: Sequelize.STRING(50), allowNull: false, references: { model: 'clients', key: 'id' }, onDelete: 'CASCADE' },
      session_id: { type: Sequelize.UUID, allowNull: false, references: { model: 'sso_sessions', key: 'id' }, onDelete: 'CASCADE' },
      user_id: { type: Sequelize.UUID, allowNull: false },
      redirect_uri: { type: Sequelize.STRING(255), allowNull: false },
      code_challenge: { type: Sequelize.STRING(128), allowNull: false },
      nonce: { type: Sequelize.STRING(255) },
      expires_at: { type: Sequelize.DATE, allowNull: false },
      used_at: { type: Sequelize.DATE },
      created_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.fn('NOW') },
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('authorization_codes');
  },
};
