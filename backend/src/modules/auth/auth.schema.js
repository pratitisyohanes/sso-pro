const { z } = require('zod');

// Same field names as the office telkom-auth/authValidate call
const validateSchema = z.object({
  body: z.object({
    username: z.string().trim().toLowerCase().email('Username must be an email address').max(150),
    password: z.string().max(200),
  }),
});

module.exports = { validateSchema };
