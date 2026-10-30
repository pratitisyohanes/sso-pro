const asyncHandler = require('../../utils/asyncHandler');
const { success } = require('../../utils/response');
const usersService = require('./users.service');

const contextOf = (req) => ({ client: req.client, ip: req.get('X-Forwarded-For') || req.ip });

const getUser = asyncHandler(async (req, res) => {
  const data = await usersService.getUser(req.params.id);
  success(res, { message: 'User detail', data });
});

const createUser = asyncHandler(async (req, res) => {
  const data = await usersService.createUser(req.body, contextOf(req));
  success(res, { statusCode: 201, message: 'User created', data });
});

const updateUser = asyncHandler(async (req, res) => {
  const data = await usersService.updateUser(req.params.id, req.body, contextOf(req));
  success(res, { message: 'User updated', data });
});

const updateStatus = asyncHandler(async (req, res) => {
  const data = await usersService.updateStatus(req.params.id, req.body, contextOf(req));
  success(res, { message: 'User access updated', data });
});

module.exports = { getUser, createUser, updateUser, updateStatus };
