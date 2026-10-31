const { Client } = require('../../src/models');

// Regression: the three address lists once shared one definition object, so they all pointed at the redirect_uris column
describe('Client model columns', () => {
  test('each address list has its own column', () => {
    const columns = ['redirectUris', 'postLogoutRedirectUris', 'allowedOrigins'].map((name) => Client.rawAttributes[name].field);
    expect(columns).toEqual(['redirect_uris', 'post_logout_redirect_uris', 'allowed_origins']);
  });

  test('an insert writes every list to its own column', () => {
    const { query, bind } = Client.queryGenerator.insertQuery(
      'clients',
      { id: 'booking-web', name: 'Booking', redirect_uris: ['callback'], post_logout_redirect_uris: ['home'], allowed_origins: ['origin'] },
      Client.getAttributes(),
      {},
    );
    expect(query).toContain('"redirect_uris"');
    expect(query).toContain('"post_logout_redirect_uris"');
    expect(query).toContain('"allowed_origins"');
    expect(JSON.stringify(bind)).toMatch(/callback.*home.*origin/);
  });
});
