module.exports = {
  async up(queryInterface, Sequelize) {
    await queryInterface.createTable('auth_events', {
      id: { type: Sequelize.BIGINT, primaryKey: true, autoIncrement: true, allowNull: false },
      client_id: { type: Sequelize.STRING(50), allowNull: false, references: { model: 'clients', key: 'id' }, onDelete: 'CASCADE' },
      action: { type: Sequelize.STRING(30), allowNull: false },
      result: { type: Sequelize.STRING(30), allowNull: false },
      username: { type: Sequelize.STRING(150) },
      user_id: { type: Sequelize.UUID },
      ip: { type: Sequelize.STRING(45) },
      created_at: { type: Sequelize.DATE, allowNull: false, defaultValue: Sequelize.fn('NOW') },
    });
    await queryInterface.addIndex('auth_events', ['username', 'created_at']);
    await queryInterface.addIndex('auth_events', ['created_at']);
  },

  async down(queryInterface) {
    await queryInterface.dropTable('auth_events');
  },
};
