// Refresh tokens are rotated: each use revokes the old row and creates a new one in the same session
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('refresh_tokens', {
      id: { type: Sequelize.UUID, primaryKey: true, allowNull: false },
      token_hash: { type: Sequelize.STRING(64), allowNull: false, unique: true },
      session_id: { type: Sequelize.UUID, allowNull: false, references: { model: 'sso_sessions', key: 'id' }, onDelete: 'CASCADE' },
      client_id: { type: Sequelize.STRING(50), allowNull: false, references: { model: 'clients', key: 'id' }, onDelete: 'CASCADE' },
      user_id: { type: Sequelize.UUID, allowNull: false },
      expires_at: { type: Sequelize.DATE, allowNull: false },
      revoked_at: { type: Sequelize.DATE },
      created_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.fn('NOW') },
    });
    await queryInterface.addIndex('refresh_tokens', ['session_id']);
  },

  async down(queryInterface) {
    await queryInterface.dropTable('refresh_tokens');
  },
};
