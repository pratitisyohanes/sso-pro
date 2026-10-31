const nodemailer = require('nodemailer');
const env = require('../config/env');

let transporter;

// Created on first use, so the app starts fine without any SMTP settings
const getTransporter = () => {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      secure: env.SMTP_SECURE,
      auth: { user: env.SMTP_USER, pass: env.SMTP_PASSWORD },
      connectionTimeout: 10_000,
      socketTimeout: 15_000,
    });
  }
  return transporter;
};

const send = ({ to, subject, text }) => {
  if (!env.MAIL_ENABLED) return Promise.reject(new Error('Email is not configured (SMTP_* in .env)'));
  return getTransporter().sendMail({ from: env.MAIL_FROM, to, subject, text });
};

const sendPasswordReset = ({ to, name, link, minutes }) =>
  send({
    to,
    subject: 'Reset your ELEFEZ FARM password',
    text: [
      `Hello ${name},`,
      '',
      'Someone asked to reset the password of your ELEFEZ FARM account. Open this link to choose a new password:',
      '',
      link,
      '',
      `The link works once and expires in ${minutes} minutes.`,
      'If you did not ask for this, ignore this email; your password stays the same.',
    ].join('\n'),
  });

const sendPasswordChanged = ({ to, name }) =>
  send({
    to,
    subject: 'Your ELEFEZ FARM password was changed',
    text: [
      `Hello ${name},`,
      '',
      'The password of your ELEFEZ FARM account was just changed, and you were logged out on your other devices.',
      'If this was not you, reset your password right away from the login page and contact the farm.',
    ].join('\n'),
  });

module.exports = { sendPasswordReset, sendPasswordChanged };
