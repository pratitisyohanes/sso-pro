module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('clients', {
      id: { type: Sequelize.STRING(50), primaryKey: true, allowNull: false },
      name: { type: Sequelize.STRING(100), allowNull: false },
      secret_hash: { type: Sequelize.TEXT, allowNull: false },
      scopes: { type: Sequelize.ARRAY(Sequelize.STRING(30)), allowNull: false, defaultValue: [] },
      is_active: { type: Sequelize.BOOLEAN, allowNull: false, defaultValue: true },
      created_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.fn('NOW') },
      updated_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.fn('NOW') },
    });
  },

  async down(queryInterface) {
    await queryInterface.dropTable('clients');
  },
};
