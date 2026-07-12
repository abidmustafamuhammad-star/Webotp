'use strict';
const jwt = require('jsonwebtoken');
const config = require('../config');
const { query, queryOne } = require('./db');

function signToken(payload) {
  return jwt.sign(payload, config.server.jwtSecret, { expiresIn: config.server.jwtExpiry });
}

function verifyToken(token) {
  try { return jwt.verify(token, config.server.jwtSecret); }
  catch { return null; }
}

async function authMiddleware(req, res, next) {
  const token = req.cookies?.[config.server.cookieName]
    || (req.headers['authorization'] || '').replace('Bearer ', '');

  if (!token) return res.status(401).json({ success: false, error: 'Belum login.' });

  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ success: false, error: 'Sesi tidak valid atau sudah berakhir.' });

  const user = await queryOne('SELECT * FROM users WHERE id = ? AND status = "active"', [payload.id]);
  if (!user) return res.status(401).json({ success: false, error: 'Akun tidak ditemukan atau ditangguhkan.' });

  req.user = user;
  next();
}

async function adminMiddleware(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ success: false, error: 'Akses admin diperlukan.' });
  next();
}

module.exports = { signToken, verifyToken, authMiddleware, adminMiddleware };
