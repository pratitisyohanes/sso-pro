const { z } = require('zod');

// Fields follow RFC 6749 section 4.4 (client credentials grant)
const tokenSchema = z.object({
  body: z.object({
    grant_type: z.string({ required_error: 'grant_type is required' }),
    client_id: z.string({ required_error: 'client_id is required' }).trim().min(1).max(50),
    client_secret: z.string({ required_error: 'client_secret is required' }).min(1).max(200),
    scope: z.string().trim().max(200).optional(),
  }),
});

module.exports = { tokenSchema };
