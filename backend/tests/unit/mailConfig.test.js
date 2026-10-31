// Loads src/config/env.js fresh with the given variables, because it reads process.env once at load time
const loadEnv = (overrides) => {
  const saved = { ...process.env };
  ['SMTP_HOST', 'SMTP_PORT', 'SMTP_SECURE', 'SMTP_USER', 'SMTP_PASSWORD', 'MAIL_FROM'].forEach((key) => delete process.env[key]);
  Object.assign(process.env, overrides);
  jest.resetModules();
  try {
    // eslint-disable-next-line global-require
    return require('../../src/config/env');
  } finally {
    process.env = saved;
  }
};

describe('email settings', () => {
  test('email stays off when SMTP_HOST is empty', () => {
    const env = loadEnv({ SMTP_HOST: '' });
    expect(env.MAIL_ENABLED).toBe(false);
    expect(env.MAIL_FROM).toBeUndefined();
  });

  test('a full Gmail setup turns email on and removes the spaces from the App Password', () => {
    const env = loadEnv({ SMTP_HOST: 'smtp.gmail.com', SMTP_USER: 'farm@gmail.com', SMTP_PASSWORD: 'abcd efgh ijkl mnop' });
    expect(env.MAIL_ENABLED).toBe(true);
    expect(env.SMTP_PASSWORD).toBe('abcdefghijklmnop');
    expect(env.SMTP_PORT).toBe(465);
    expect(env.SMTP_SECURE).toBe(true);
    expect(env.MAIL_FROM).toBe('"ELEFEZ FARM" <farm@gmail.com>');
  });

  test('port 587 with STARTTLS and an explicit sender are respected', () => {
    const env = loadEnv({
      SMTP_HOST: 'smtp.gmail.com',
      SMTP_PORT: '587',
      SMTP_SECURE: 'false',
      SMTP_USER: 'farm@gmail.com',
      SMTP_PASSWORD: 'secret',
      MAIL_FROM: '"Farm Desk" <desk@example.com>',
    });
    expect(env.SMTP_PORT).toBe(587);
    expect(env.SMTP_SECURE).toBe(false);
    expect(env.MAIL_FROM).toBe('"Farm Desk" <desk@example.com>');
  });

  test('a host without credentials stops the app at startup', () => {
    const exit = jest.spyOn(process, 'exit').mockImplementation(() => {
      throw new Error('exit');
    });
    const log = jest.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => loadEnv({ SMTP_HOST: 'smtp.gmail.com' })).toThrow('exit');
    expect(JSON.stringify(log.mock.calls)).toContain('SMTP_USER is required when SMTP_HOST is set');
    exit.mockRestore();
    log.mockRestore();
  });
});
