'use strict';
const crypto = require('crypto');
const config = require('../config');

const log = {
  info:  (...a) => console.log('[INFO]',  new Date().toISOString(), ...a),
  warn:  (...a) => console.warn('[WARN]',  new Date().toISOString(), ...a),
  error: (...a) => console.error('[ERROR]', new Date().toISOString(), ...a),
};

const getIp = (req) =>
  (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || '0.0.0.0';

const sanitize = (str = '') => String(str).replace(/[<>"']/g, '').trim().slice(0, 500);

const genToken = (bytes = 32) => crypto.randomBytes(bytes).toString('hex');

const genCode = (digits = 6) => String(Math.floor(Math.random() * 10 ** digits)).padStart(digits, '0');

const formatRp = (n) => 'Rp ' + Number(n || 0).toLocaleString('id-ID');

const applyMarkup = (basePrice, markupPct) => Math.ceil(basePrice * (1 + markupPct / 100));

const genPakasirOrderId = (prefix = 'OTP') => `${prefix}${Date.now()}${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

/** Audit log ke DB (fire-and-forget) */
async function auditLog(db, userId, action, details, ip, status = 'success') {
  try {
    await db.query(
      'INSERT INTO audit_logs (user_id, action, details, ip_address, status) VALUES (?, ?, ?, ?, ?)',
      [userId || null, action, JSON.stringify(details || {}), ip, status]
    );
  } catch (e) { log.error('auditLog', e.message); }
}

/** Balance log ke DB */
async function balanceLog(conn, userId, type, amount, balanceBefore, balanceAfter, refType, refId, note) {
  await conn.execute(
    `INSERT INTO balance_logs (user_id, type, amount, balance_before, balance_after, reference_type, reference_id, note)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [userId, type, amount, balanceBefore, balanceAfter, refType, refId || null, note || null]
  );
}

/** Ambil setting dari DB dengan fallback */
async function getSetting(db, key, fallback = null) {
  const row = await db.queryOne('SELECT value FROM settings WHERE `key` = ?', [key]);
  return row ? row.value : fallback;
}

/** Update setting di DB */
async function setSetting(db, key, value) {
  await db.query('INSERT INTO settings (`key`, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = ?', [key, value, value]);
}

module.exports = { log, getIp, sanitize, genToken, genCode, formatRp, applyMarkup, genPakasirOrderId, auditLog, balanceLog, getSetting, setSetting };
