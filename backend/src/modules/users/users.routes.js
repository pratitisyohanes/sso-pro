const router = require('express').Router();
const validate = require('../../middlewares/validate');
const authenticateClient = require('../../middlewares/authenticateClient');
const controller = require('./users.controller');
const { userIdSchema, createUserSchema, updateUserSchema, updateStatusSchema } = require('./users.schema');

router.get('/:id', authenticateClient('users:read'), validate(userIdSchema), controller.getUser);
router.post('/', authenticateClient('users:write'), validate(createUserSchema), controller.createUser);
router.patch('/:id', authenticateClient('users:write'), validate(updateUserSchema), controller.updateUser);
router.patch('/:id/status', authenticateClient('users:admin'), validate(updateStatusSchema), controller.updateStatus);

module.exports = router;
