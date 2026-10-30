// PM2 process file used on the VPS: keeps auth-service running next to booking-api and pos-api
module.exports = {
  apps: [
    {
      name: 'sso-api',
      script: 'src/server.js',
      cwd: __dirname,
      instances: 1,
      exec_mode: 'fork',
      env: { NODE_ENV: 'production' },
      // Smallest of the three services; the 1 GB VPS also runs PostgreSQL and slapd
      max_memory_restart: '200M',
      time: true,
    },
  ],
};
