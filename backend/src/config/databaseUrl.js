// Build DATABASE_URL from Laravel-style DB_* variables when it is not set directly
const applyDatabaseUrl = (env = process.env) => {
  if (env.DATABASE_URL || !env.DB_HOST) return;

  const { DB_HOST, DB_PORT = '5432', DB_DATABASE = '', DB_USERNAME = '', DB_PASSWORD = '' } = env;
  // Encode credentials so characters like @ : / # in a password do not break the URL
  const credentials = DB_PASSWORD
    ? `${encodeURIComponent(DB_USERNAME)}:${encodeURIComponent(DB_PASSWORD)}`
    : encodeURIComponent(DB_USERNAME);

  env.DATABASE_URL = `postgresql://${credentials}@${DB_HOST}:${DB_PORT}/${DB_DATABASE}`;
};

module.exports = applyDatabaseUrl;
