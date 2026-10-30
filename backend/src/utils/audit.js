const { AuthEvent } = require('../models');

// Write one audit row; a logging failure must never block a login
const audit = async ({ client, action, result, username, userId, ip }) => {
  try {
    await AuthEvent.create({ clientId: client?.id ?? null, action, result, username, userId, ip });
  } catch (error) {
    console.error('Failed to write auth event:', error.message);
  }
};

module.exports = audit;
