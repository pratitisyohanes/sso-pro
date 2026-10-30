const { z } = require('zod');

// Same password and phone rules as booking-api so both reject the same input
const password = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .max(72, 'Password must be at most 72 characters')
  .regex(/[A-Za-z]/, 'Password must contain a letter')
  .regex(/\d/, 'Password must contain a number');

const phone = z.string().trim().regex(/^\+?[0-9]{8,15}$/, 'Phone must be 8-15 digits');

const userIdSchema = z.object({ params: z.object({ id: z.string().uuid('User id must be a UUID') }) });

const createUserSchema = z.object({
  body: z
    .object({
      // Optional so existing booking users can be imported with the id they already have
      id: z.string().uuid().optional(),
      name: z.string().trim().min(2, 'Name must be at least 2 characters').max(100),
      email: z.string().trim().toLowerCase().email('Email is not valid').max(150),
      phone: phone.optional(),
      password,
    })
    .strict('Unknown field; role and groups cannot be set here'),
});

const updateUserSchema = z.object({
  params: userIdSchema.shape.params,
  body: z
    .object({
      name: z.string().trim().min(2).max(100).optional(),
      phone: phone.nullable().optional(),
      currentPassword: z.string().min(1).optional(),
      newPassword: password.optional(),
    })
    .strict()
    .refine((data) => Object.keys(data).length > 0, 'Provide at least one field to update')
    .refine((data) => !data.newPassword || data.currentPassword, {
      message: 'Current password is required to set a new password',
      path: ['currentPassword'],
    }),
});

const updateStatusSchema = z.object({
  params: userIdSchema.shape.params,
  body: z
    .object({
      role: z.enum(['ADMIN', 'USER']).optional(),
      disabled: z.boolean().optional(),
    })
    .strict()
    .refine((data) => data.role !== undefined || data.disabled !== undefined, 'Provide role or disabled'),
});

module.exports = { userIdSchema, createUserSchema, updateUserSchema, updateStatusSchema };
