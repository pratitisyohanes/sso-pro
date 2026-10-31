const { z } = require('zod');

// Pages receive form posts, so every value arrives as a string
const loginFormSchema = z.object({
  email: z.string().trim().toLowerCase().email('Enter a valid email address').max(150),
  password: z.string().min(1, 'Enter your password').max(200),
});

const codeFormSchema = z.object({ code: z.string().trim().regex(/^\d{6}$/, 'Enter the 6-digit code') });

const registerFormSchema = z
  .object({
    name: z.string().trim().min(2, 'Name must be at least 2 characters').max(100),
    email: z.string().trim().toLowerCase().email('Enter a valid email address').max(150),
    // Optional: empty (or just "-") means no phone; spaces, dashes and brackets are dropped before the digit check
    phone: z
      .string()
      .default('')
      .transform((value) => value.replace(/[\s().-]/g, ''))
      .pipe(z.string().regex(/^(\+?[0-9]{8,15})?$/, 'Phone must be 8-15 digits'))
      .transform((value) => value || undefined),
    password: z
      .string()
      .min(8, 'Password must be at least 8 characters')
      .max(72)
      .regex(/[A-Za-z]/, 'Password must contain a letter')
      .regex(/\d/, 'Password must contain a number'),
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, { message: 'Passwords do not match', path: ['confirmPassword'] });

// First message per field, for showing under each input
const fieldErrors = (zodError) =>
  zodError.issues.reduce((acc, issue) => {
    const field = issue.path[0];
    if (field && !acc[field]) acc[field] = issue.message;
    return acc;
  }, {});

module.exports = { loginFormSchema, codeFormSchema, registerFormSchema, fieldErrors };
