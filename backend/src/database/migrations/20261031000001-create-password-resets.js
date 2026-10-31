// One row per "forgot password" email. Only the SHA-256 of the token is stored, like refresh tokens and session ids
module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('password_resets', {
      id: { type: Sequelize.UUID, primaryKey: true, allowNull: false },
      user_id: { type: Sequelize.UUID, allowNull: false },
      token_hash: { type: Sequelize.STRING(64), allowNull: false, unique: true },
      expires_at: { type: Sequelize.DATE, allowNull: false },
      // Set when the link is used, or when a newer request replaces it
      used_at: { type: Sequelize.DATE },
      ip: { type: Sequelize.STRING(45) },
      created_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.fn('NOW') },
    });
    // Counting a user's recent requests is how the hourly limit works
    await queryInterface.addIndex('password_resets', ['user_id', 'created_at']);
  },

  async down(queryInterface) {
    await queryInterface.dropTable('password_resets');
  },
};
