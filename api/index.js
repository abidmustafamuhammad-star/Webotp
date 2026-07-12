'use strict';
const express    = require('express');
const path       = require('path');
const cors       = require('cors');
const cookieParser = require('cookie-parser');
const crypto     = require('crypto');
const bcrypt     = require('bcryptjs');

const config     = require('../config');
const db         = require('../lib/db');
const rumahotp   = require('../lib/rumahotp');
const pakasir    = require('../lib/pakasir');
const tg         = require('../lib/telegram');
const { signToken, authMiddleware, adminMiddleware } = require('../lib/auth');
const {
  log, getIp, sanitize, genToken, genCode,
  formatRp, applyMarkup, genPakasirOrderId,
  auditLog, balanceLog, getSetting, setSetting,
} = require('../lib/helpers');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: true, limit: '20kb' }));
app.use(cookieParser());
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(path.join(__dirname, '../public')));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

// Maintenance mode check (skip admin & webhook)
app.use(async (req, res, next) => {
  if (req.path.startsWith('/api/admin') || req.path.startsWith('/webhook') || req.path.startsWith('/api/auth')) return next();
  try {
    const mode = await getSetting(db, 'maintenance_mode', '0');
    if (mode === '1') return res.status(503).json({ success: false, error: 'Website sedang dalam maintenance. Coba lagi nanti.', maintenance: true });
  } catch {}
  next();
});

// Simple in-process rate limiter
const rateStore = new Map();
app.use('/api/', (req, res, next) => {
  const key = getIp(req);
  const now = Date.now();
  const r = rateStore.get(key);
  if (!r || now > r.reset) { rateStore.set(key, { count: 1, reset: now + config.security.rateLimitWindow }); return next(); }
  if (r.count >= config.security.rateLimitMax) return res.status(429).json({ success: false, error: 'Terlalu banyak request. Tunggu sebentar.' });
  r.count++; next();
});

// ============================================================
// STATIC PAGES
// ============================================================
const pub = (file) => (req, res) => res.sendFile(path.join(__dirname, '../public', file));
app.get('/',              pub('index.html'));
app.get('/login',         pub('login.html'));
app.get('/register',      pub('register.html'));
app.get('/dashboard',     pub('dashboard.html'));
app.get('/order',         pub('order.html'));
app.get('/payment',       pub('payment.html'));
app.get('/status',        pub('status.html'));
app.get('/developer/api', pub('developer.html'));
app.get('/about',         pub('about.html'));
app.get('/blog',          pub('blog.html'));
app.get('/privacy',       pub('privacy.html'));
app.get('/terms',         pub('terms.html'));
app.get('/refund',        pub('refund.html'));
app.get('/admin',         pub('admin.html'));
app.get('/health',        (req, res) => res.json({ ok: true }));

// ============================================================
// AUTH — REGISTER
// ============================================================
const loginAttempts = new Map();
app.post('/api/auth/register', async (req, res) => {
  const ip = getIp(req);
  try {
    let { username, email, password } = req.body;
    username = sanitize(String(username || '')).toLowerCase();
    email    = sanitize(String(email    || '')).toLowerCase();
    password = String(password || '');

    if (!username || !email || !password) return res.status(400).json({ success: false, error: 'Semua field wajib diisi.' });
    if (!/^[a-z0-9_]{3,30}$/.test(username)) return res.status(400).json({ success: false, error: 'Username 3-30 karakter: huruf kecil, angka, underscore.' });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ success: false, error: 'Format email tidak valid.' });
    if (password.length < config.security.minPassword) return res.status(400).json({ success: false, error: `Password minimal ${config.security.minPassword} karakter.` });

    const existing = await db.queryOne('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
    if (existing) return res.status(409).json({ success: false, error: 'Username atau email sudah terdaftar.' });

    const hash  = await bcrypt.hash(password, config.security.bcryptRounds);
    const count = (await db.queryOne('SELECT COUNT(*) AS c FROM users', []))?.c || 0;
    const role  = count === 0 ? 'admin' : 'user';

    const [ins] = await db.getPool().execute(
      'INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)',
      [username, email, hash, role]
    );
    await auditLog(db, ins.insertId, 'register', { username, email, role }, ip);
    res.json({ success: true, message: 'Registrasi berhasil! Silakan login.', role });
  } catch (e) { log.error('register', e.message); res.status(500).json({ success: false, error: 'Gagal mendaftar.' }); }
});

// ============================================================
// AUTH — LOGIN STEP 1: validasi kredensial, kirim kode Telegram
// ============================================================
app.post('/api/auth/login', async (req, res) => {
  const ip = getIp(req);
  try {
    const attempt = loginAttempts.get(ip);
    if (attempt?.until && Date.now() < attempt.until) {
      const wait = Math.ceil((attempt.until - Date.now()) / 60000);
      return res.status(429).json({ success: false, error: `Terlalu banyak percobaan. Coba ${wait} menit lagi.` });
    }

    let { login, password } = req.body;
    login    = sanitize(String(login    || '')).toLowerCase();
    password = String(password || '');
    if (!login || !password) return res.status(400).json({ success: false, error: 'Username/email dan password wajib diisi.' });

    const isEmail = login.includes('@');
    const user    = await db.queryOne(`SELECT * FROM users WHERE ${isEmail ? 'email' : 'username'} = ?`, [login]);
    const valid   = user && await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      const cur = loginAttempts.get(ip) || { count: 0, until: null };
      cur.count++;
      if (cur.count >= config.security.maxLoginAttempts) cur.until = Date.now() + config.security.lockoutMs;
      loginAttempts.set(ip, cur);
      await auditLog(db, user?.id, 'login_failed', { login }, ip, 'failed');
      return res.status(401).json({ success: false, error: 'Username/email atau password salah.' });
    }
    if (user.status !== 'active') return res.status(403).json({ success: false, error: 'Akun ditangguhkan. Hubungi admin.' });
    loginAttempts.delete(ip);

    // Jika belum tautkan Telegram → login langsung tanpa 2FA
    if (!user.telegram_chat_id) {
      const token = signToken({ id: user.id, role: user.role });
      res.cookie(config.server.cookieName, token, {
        httpOnly: true, secure: config.server.secureCookie, sameSite: 'lax', maxAge: 7 * 86400 * 1000,
      });
      await auditLog(db, user.id, 'login_direct', { login, note: 'no_telegram' }, ip);
      return res.json({ success: true, twofa: false, user: { id: user.id, username: user.username, role: user.role } });
    }

    // Ada Telegram → kirim kode 6-digit
    const code = genCode(6);
    const expiresAt = new Date(Date.now() + config.security.otpCodeExpirySec * 1000);

    await db.getPool().execute(
      'INSERT INTO login_verifications (user_id, code, expires_at, ip_address) VALUES (?, ?, ?, ?)',
      [user.id, code, expiresAt, ip]
    );

    await tg.sendLoginCode(user.telegram_chat_id, code, config.site.name);
    await auditLog(db, user.id, 'login_otp_sent', { login }, ip);

    res.json({ success: true, twofa: true, user_id: user.id, message: `Kode verifikasi telah dikirim ke Telegram kamu.` });
  } catch (e) { log.error('login', e.message); res.status(500).json({ success: false, error: 'Gagal login.' }); }
});

// ============================================================
// AUTH — LOGIN STEP 2: verifikasi kode Telegram
// ============================================================
app.post('/api/auth/verify-login', async (req, res) => {
  const ip = getIp(req);
  try {
    const { user_id, code } = req.body;
    if (!user_id || !code) return res.status(400).json({ success: false, error: 'Data tidak lengkap.' });

    const row = await db.queryOne(
      'SELECT * FROM login_verifications WHERE user_id = ? AND used = 0 AND expires_at > NOW() ORDER BY id DESC LIMIT 1',
      [user_id]
    );
    if (!row) return res.status(400).json({ success: false, error: 'Kode tidak ditemukan atau sudah kedaluwarsa.' });
    if (row.attempts >= config.security.otpMaxAttempts) return res.status(429).json({ success: false, error: 'Terlalu banyak percobaan. Minta kode baru.' });

    if (row.code !== String(code).trim()) {
      await db.query('UPDATE login_verifications SET attempts = attempts + 1 WHERE id = ?', [row.id]);
      return res.status(400).json({ success: false, error: 'Kode salah.' });
    }

    await db.query('UPDATE login_verifications SET used = 1 WHERE id = ?', [row.id]);
    const user = await db.queryOne('SELECT * FROM users WHERE id = ?', [user_id]);
    if (!user || user.status !== 'active') return res.status(403).json({ success: false, error: 'Akun tidak valid.' });

    const token = signToken({ id: user.id, role: user.role });
    res.cookie(config.server.cookieName, token, {
      httpOnly: true, secure: config.server.secureCookie, sameSite: 'lax', maxAge: 7 * 86400 * 1000,
    });
    await auditLog(db, user.id, 'login_verified', {}, ip);
    res.json({ success: true, user: { id: user.id, username: user.username, role: user.role } });
  } catch (e) { log.error('verify-login', e.message); res.status(500).json({ success: false, error: 'Gagal verifikasi.' }); }
});

// ============================================================
// AUTH — LOGOUT
// ============================================================
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie(config.server.cookieName);
  res.json({ success: true });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const u = req.user;
  res.json({ success: true, user: { id: u.id, username: u.username, email: u.email, role: u.role, balance: u.balance, telegram_linked: !!u.telegram_chat_id } });
});

// ============================================================
// TELEGRAM LINK — user tautkan akun Telegram
// ============================================================
/** Hasilkan token unik, user harus kirim "/link <token>" ke bot */
app.post('/api/auth/telegram/generate-link', authMiddleware, async (req, res) => {
  try {
    const token     = genToken(16);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 menit
    await db.getPool().execute(
      'INSERT INTO telegram_link_tokens (user_id, token, expires_at) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE token = ?, expires_at = ?, used = 0',
      [req.user.id, token, expiresAt, token, expiresAt]
    );
    const me = await tg.getMe().catch(() => ({ result: { username: 'YourBot' } }));
    res.json({ success: true, token, bot_username: me.result?.username, expires_at: expiresAt });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal membuat token.' }); }
});

// ============================================================
// TELEGRAM WEBHOOK — bot menerima pesan /link <token>
// ============================================================
app.post('/webhook/telegram', async (req, res) => {
  res.sendStatus(200); // selalu oke dulu
  try {
    const { message } = req.body;
    if (!message?.text) return;
    const chatId   = String(message.chat.id);
    const username = message.from?.username || '';
    const text     = message.text.trim();

    if (text.startsWith('/link ')) {
      const token = text.split(' ')[1]?.trim();
      if (!token) return;
      const row = await db.queryOne(
        'SELECT * FROM telegram_link_tokens WHERE token = ? AND used = 0 AND expires_at > NOW()',
        [token]
      );
      if (!row) { await tg.sendMessage(chatId, '❌ Token tidak valid atau sudah kedaluwarsa. Minta token baru di website.'); return; }

      await db.getPool().execute('UPDATE users SET telegram_chat_id = ?, telegram_username = ? WHERE id = ?', [chatId, username, row.user_id]);
      await db.getPool().execute('UPDATE telegram_link_tokens SET used = 1 WHERE id = ?', [row.id]);
      await tg.sendMessage(chatId, `✅ Akun Telegram berhasil ditautkan ke akun ${config.site.name} kamu!\n\nMulai sekarang, kode login akan dikirim ke sini.`);
    }

    if (text === '/start') {
      await tg.sendMessage(chatId, `👋 Halo! Ini adalah bot resmi <b>${config.site.name}</b>.\n\nUntuk menautkan akun, pergi ke website → Dashboard → Tautkan Telegram, lalu kirim perintah:\n<code>/link TOKEN_KAMU</code>`, 'HTML');
    }
  } catch (e) { log.error('telegram webhook', e.message); }
});

// ============================================================
// CATALOG — RumahOTP
// ============================================================
app.get('/api/catalog/services', authMiddleware, async (req, res) => {
  try { res.json({ success: true, ...await rumahotp.getServices() }); }
  catch (e) { res.status(502).json({ success: false, error: 'Gagal mengambil daftar layanan.' }); }
});

app.get('/api/catalog/countries', authMiddleware, async (req, res) => {
  const { service_id } = req.query;
  if (!service_id) return res.status(400).json({ success: false, error: 'service_id diperlukan.' });
  try { res.json({ success: true, ...await rumahotp.getCountries(service_id) }); }
  catch (e) { res.status(502).json({ success: false, error: 'Gagal mengambil daftar negara.' }); }
});

app.get('/api/catalog/operators', authMiddleware, async (req, res) => {
  const { country, provider_id } = req.query;
  if (!country || !provider_id) return res.status(400).json({ success: false, error: 'country dan provider_id diperlukan.' });
  try { res.json({ success: true, ...await rumahotp.getOperators(country, provider_id) }); }
  catch (e) { res.status(502).json({ success: false, error: 'Gagal mengambil operator.' }); }
});

// ============================================================
// ORDER — buat pesanan (setelah pembayaran sukses → dipanggil internal)
// ============================================================
async function fulfillOrder(orderId) {
  const order = await db.queryOne('SELECT * FROM orders WHERE id = ?', [orderId]);
  if (!order || order.status !== 'paid') return;

  try {
    const result = await rumahotp.createOrder({
      number_id:   order.number_id,
      provider_id: order.provider_id,
      operator_id: order.operator_id,
    });
    const data = result?.data || result;
    const phone          = data?.phone_number || data?.number || '';
    const rumahOrderId   = data?.order_id     || data?.id     || '';

    await db.getPool().execute(
      `UPDATE orders SET status = 'number_issued', phone_number = ?, rumahotp_order_id = ?, updated_at = NOW() WHERE id = ?`,
      [phone, rumahOrderId, orderId]
    );

    // Kirim notif Telegram jika ada
    const user = await db.queryOne('SELECT telegram_chat_id FROM users WHERE id = ?', [order.user_id]);
    if (user?.telegram_chat_id) {
      await tg.sendPaymentNotification(user.telegram_chat_id, order.price, config.site.name);
    }
  } catch (e) {
    log.error('fulfillOrder', e.message);
    await db.getPool().execute(`UPDATE orders SET status = 'cancelled', updated_at = NOW() WHERE id = ?`, [orderId]);
    // Refund user
    await db.transaction(async (conn) => {
      const u = await conn.execute('SELECT balance FROM users WHERE id = ? FOR UPDATE', [order.user_id]);
      const bal = u[0][0].balance;
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [order.price, order.user_id]);
      await balanceLog(conn, order.user_id, 'credit', order.price, bal, Number(bal) + Number(order.price), 'refund', order.id, 'Gagal ambil nomor dari provider');
    });
  }
}

/** User buat pesanan (sebelum bayar) */
app.post('/api/order/create', authMiddleware, async (req, res) => {
  const ip = getIp(req);
  try {
    let { service_id, service_name, country, country_name, provider_id, operator_id, number_id, base_price } = req.body;
    if (!service_id || !country || !provider_id || !operator_id || !number_id)
      return res.status(400).json({ success: false, error: 'Parameter pesanan tidak lengkap.' });

    base_price = parseFloat(base_price || 0);
    const markupPct = parseFloat(await getSetting(db, 'markup_percent', '15'));
    const price     = applyMarkup(base_price, markupPct);

    const [ins] = await db.getPool().execute(
      `INSERT INTO orders (user_id, service_id, service_name, country, country_name, provider_id, operator_id, number_id, base_price, price, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_payment')`,
      [req.user.id, service_id, sanitize(service_name || ''), country, sanitize(country_name || ''), provider_id, operator_id, number_id, base_price, price]
    );
    const orderId    = ins.insertId;
    const pakasirId  = genPakasirOrderId();

    let qrData;
    try {
      qrData = await pakasir.createQris(pakasirId, price);
    } catch (e) {
      await db.getPool().execute('DELETE FROM orders WHERE id = ?', [orderId]);
      return res.status(502).json({ success: false, error: 'Gagal membuat pembayaran QRIS. Coba lagi.' });
    }

    await db.getPool().execute(
      `INSERT INTO transactions (order_id, user_id, pakasir_order_id, amount, qr_string, expired_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [orderId, req.user.id, pakasirId, price, qrData?.qr_string || '', qrData?.expired_at ? new Date(qrData.expired_at) : new Date(Date.now() + 5 * 60000)]
    );

    await auditLog(db, req.user.id, 'order_create', { order_id: orderId, service_id, price }, ip);
    res.json({ success: true, order_id: orderId, pakasir_order_id: pakasirId, amount: price, qr_string: qrData?.qr_string, expired_at: qrData?.expired_at });
  } catch (e) { log.error('order/create', e.message); res.status(500).json({ success: false, error: 'Gagal membuat pesanan.' }); }
});

/** Cek status pembayaran (polling dari client) */
app.get('/api/order/:id/payment-status', authMiddleware, async (req, res) => {
  try {
    const order = await db.queryOne('SELECT * FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!order) return res.status(404).json({ success: false, error: 'Pesanan tidak ditemukan.' });
    const tx = await db.queryOne('SELECT * FROM transactions WHERE order_id = ?', [order.id]);
    res.json({ success: true, order_status: order.status, tx_status: tx?.status || 'pending', qr_string: tx?.qr_string });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal cek status.' }); }
});

/** Cek status nomor/OTP (polling) */
app.get('/api/order/:id/otp-status', authMiddleware, async (req, res) => {
  try {
    const order = await db.queryOne('SELECT * FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!order) return res.status(404).json({ success: false, error: 'Pesanan tidak ditemukan.' });

    if (['number_issued', 'otp_received'].includes(order.status) && order.rumahotp_order_id) {
      try {
        const result  = await rumahotp.getOrderStatus(order.rumahotp_order_id);
        const data    = result?.data || result;
        const status  = data?.status  || '';
        const otpCode = data?.otp_code || data?.code || null;
        const otpMsg  = data?.otp_msg  || null;

        if (otpCode && !order.otp_code) {
          await db.getPool().execute(
            `UPDATE orders SET otp_code = ?, otp_message = ?, status = 'otp_received', updated_at = NOW() WHERE id = ?`,
            [otpCode, otpMsg, order.id]
          );
          order.otp_code = otpCode; order.otp_message = otpMsg; order.status = 'otp_received';
          // Notif Telegram
          const user = await db.queryOne('SELECT telegram_chat_id FROM users WHERE id = ?', [order.user_id]);
          if (user?.telegram_chat_id) {
            await tg.sendOtpNotification(user.telegram_chat_id, order.service_name, order.phone_number, otpCode, config.site.name);
          }
        }

        if (['EXPIRED','CANCELED'].includes(status) && !order.otp_code) {
          await db.getPool().execute(`UPDATE orders SET status = 'expired', updated_at = NOW() WHERE id = ?`, [order.id]);
          order.status = 'expired';
        }
      } catch (e) { log.warn('otp-poll', e.message); }
    }

    res.json({ success: true, order: { id: order.id, status: order.status, phone_number: order.phone_number, otp_code: order.otp_code, otp_message: order.otp_message } });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal cek status OTP.' }); }
});

/** Cancel order */
app.post('/api/order/:id/cancel', authMiddleware, async (req, res) => {
  const ip = getIp(req);
  try {
    const order = await db.queryOne('SELECT * FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!order) return res.status(404).json({ success: false, error: 'Pesanan tidak ditemukan.' });
    if (!['pending_payment', 'paid', 'number_issued'].includes(order.status))
      return res.status(400).json({ success: false, error: 'Pesanan tidak dapat dibatalkan.' });

    if (order.rumahotp_order_id) {
      try { await rumahotp.setOrderStatus(order.rumahotp_order_id, 'cancel'); } catch (e) { log.warn('cancel rumahotp', e.message); }
    }
    const tx = await db.queryOne('SELECT * FROM transactions WHERE order_id = ?', [order.id]);
    if (tx && tx.status === 'pending') {
      try { await pakasir.cancelTransaction(tx.pakasir_order_id, tx.amount); } catch (e) { log.warn('cancel pakasir', e.message); }
      await db.getPool().execute(`UPDATE transactions SET status = 'cancelled', updated_at = NOW() WHERE id = ?`, [tx.id]);
    }
    await db.getPool().execute(`UPDATE orders SET status = 'cancelled', updated_at = NOW() WHERE id = ?`, [order.id]);
    await auditLog(db, req.user.id, 'order_cancel', { order_id: order.id }, ip);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal membatalkan.' }); }
});

/** Riwayat order user */
app.get('/api/user/orders', authMiddleware, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page  || '1'));
    const limit = Math.min(50, parseInt(req.query.limit || '20'));
    const total = (await db.queryOne('SELECT COUNT(*) AS c FROM orders WHERE user_id = ?', [req.user.id]))?.c || 0;
    const data  = await db.query('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?', [req.user.id, limit, (page - 1) * limit]);
    res.json({ success: true, data, total, page, limit });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal mengambil riwayat.' }); }
});

/** Riwayat transaksi user */
app.get('/api/user/transactions', authMiddleware, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page  || '1'));
    const limit = Math.min(50, parseInt(req.query.limit || '20'));
    const total = (await db.queryOne('SELECT COUNT(*) AS c FROM transactions WHERE user_id = ?', [req.user.id]))?.c || 0;
    const data  = await db.query('SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?', [req.user.id, limit, (page - 1) * limit]);
    res.json({ success: true, data, total, page, limit });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal mengambil transaksi.' }); }
});

// ============================================================
// WEBHOOK — PAKASIR
// ============================================================
app.post('/webhook/pakasir', async (req, res) => {
  res.sendStatus(200);
  const ip = getIp(req);
  try {
    const { order_id, status, amount } = req.body || {};
    if (!order_id || !amount) return;
    if (status !== 'success' && status !== 'completed') return;

    const tx = await db.queryOne('SELECT * FROM transactions WHERE pakasir_order_id = ?', [order_id]);
    if (!tx || tx.processed) return; // idempotent

    // Verifikasi independen ke Pakasir (anti-spoofing)
    let verified = false;
    try {
      const detail  = await pakasir.getDetail(order_id, amount);
      verified = (detail?.status === 'success' || detail?.status === 'completed') && Number(detail?.amount) === Number(amount);
    } catch (e) { log.warn('pakasir verify', e.message); verified = true; } // lanjut jika API Pakasir down

    if (!verified) { log.warn('pakasir webhook: amount mismatch', { order_id, amount, tx_amount: tx.amount }); return; }
    if (Number(tx.amount) !== Number(amount)) return;

    // Tandai proses (idempotency lock)
    const [upd] = await db.getPool().execute(
      'UPDATE transactions SET status = "success", processed = 1, webhook_received = 1, raw_webhook_payload = ?, updated_at = NOW() WHERE id = ? AND processed = 0',
      [JSON.stringify(req.body), tx.id]
    );
    if (upd.affectedRows === 0) return;

    await db.getPool().execute(`UPDATE orders SET status = 'paid', updated_at = NOW() WHERE id = ?`, [tx.order_id]);
    await auditLog(db, tx.user_id, 'payment_success', { order_id, amount }, ip);

    // Fulfill nomor dari RumahOTP
    await fulfillOrder(tx.order_id);
  } catch (e) { log.error('webhook/pakasir', e.message); }
});

// ============================================================
// CRON — auto-cancel order expired
// ============================================================
app.all('/api/cron/auto-cancel', async (req, res) => {
  const secret = req.headers['x-cron-secret'] || req.query.secret || '';
  if (!config.server.cronSecret || secret !== config.server.cronSecret)
    return res.status(401).json({ success: false, error: 'Unauthorized.' });
  try {
    const cancelMinutes = parseInt(await getSetting(db, 'auto_cancel_min', '20'));
    const stale = await db.query(
      `SELECT o.*, t.id AS tx_id, t.pakasir_order_id, t.amount AS tx_amount
       FROM orders o
       LEFT JOIN transactions t ON t.order_id = o.id
       WHERE o.status IN ('pending_payment','paid','number_issued')
         AND o.created_at < DATE_SUB(NOW(), INTERVAL ? MINUTE)`,
      [cancelMinutes]
    );
    let cancelled = 0;
    for (const o of stale) {
      try {
        if (o.rumahotp_order_id) { try { await rumahotp.setOrderStatus(o.rumahotp_order_id, 'cancel'); } catch {} }
        if (o.pakasir_order_id && o.status === 'pending_payment') { try { await pakasir.cancelTransaction(o.pakasir_order_id, o.tx_amount); } catch {} }
        await db.getPool().execute(`UPDATE orders SET status = 'expired', updated_at = NOW() WHERE id = ?`, [o.id]);
        await db.getPool().execute(`UPDATE transactions SET status = 'cancelled', updated_at = NOW() WHERE order_id = ? AND status = 'pending'`, [o.id]);
        cancelled++;
      } catch (e) { log.error('cron auto-cancel', e.message); }
    }
    res.json({ success: true, scanned: stale.length, cancelled });
  } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ============================================================
// ADMIN — STATS
// ============================================================
app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [users, orders, txRevenue, activeOrders, provBalance] = await Promise.all([
      db.queryOne('SELECT COUNT(*) AS c FROM users'),
      db.queryOne('SELECT COUNT(*) AS c FROM orders'),
      db.queryOne('SELECT COALESCE(SUM(amount),0) AS total, COALESCE(SUM(amount - (SELECT o.base_price FROM orders o WHERE o.id = transactions.order_id)),0) AS profit FROM transactions WHERE status = "success"'),
      db.queryOne('SELECT COUNT(*) AS c FROM orders WHERE status IN ("number_issued","otp_received")'),
      rumahotp.getBalance().catch(() => null),
    ]);
    res.json({ success: true, stats: { total_users: users?.c, total_orders: orders?.c, revenue: txRevenue?.total || 0, profit: txRevenue?.profit || 0, active_orders: activeOrders?.c, provider_balance: provBalance?.data?.balance } });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal mengambil statistik.' }); }
});

app.get('/api/admin/stats/daily', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const rows = await db.query(
      `SELECT DATE(t.created_at) AS date, COUNT(*) AS orders, SUM(t.amount) AS revenue
       FROM transactions t WHERE t.status = 'success' AND t.created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
       GROUP BY DATE(t.created_at) ORDER BY date ASC`
    );
    res.json({ success: true, data: rows });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal mengambil statistik harian.' }); }
});

// ============================================================
// ADMIN — USERS
// ============================================================
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const q     = sanitize(req.query.q || '');
    const page  = Math.max(1, parseInt(req.query.page  || '1'));
    const limit = Math.min(100, parseInt(req.query.limit || '30'));
    const where = q ? 'WHERE username LIKE ? OR email LIKE ?' : '';
    const params = q ? [`%${q}%`, `%${q}%`] : [];
    const total = (await db.queryOne(`SELECT COUNT(*) AS c FROM users ${where}`, params))?.c || 0;
    const users = await db.query(`SELECT id,username,email,role,status,balance,telegram_chat_id,created_at FROM users ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`, [...params, limit, (page - 1) * limit]);
    res.json({ success: true, data: users, total, page, limit });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal mengambil users.' }); }
});

app.post('/api/admin/users/:id/balance', authMiddleware, adminMiddleware, async (req, res) => {
  const ip = getIp(req);
  try {
    const uid    = parseInt(req.params.id);
    const amount = parseFloat(req.body.amount);
    const note   = sanitize(req.body.note || '');
    if (!uid || isNaN(amount) || amount === 0) return res.status(400).json({ success: false, error: 'Data tidak valid.' });

    await db.transaction(async (conn) => {
      const [rows] = await conn.execute('SELECT balance FROM users WHERE id = ? FOR UPDATE', [uid]);
      if (!rows[0]) throw new Error('User tidak ditemukan.');
      const bal = rows[0].balance;
      if (amount < 0 && bal + amount < 0) throw new Error('Saldo tidak cukup.');
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, uid]);
      await balanceLog(conn, uid, amount > 0 ? 'credit' : 'debit', Math.abs(amount), bal, Number(bal) + amount, 'admin_adjust', null, note);
    });
    await auditLog(db, req.user.id, 'admin_balance_adjust', { target: uid, amount, note }, ip);
    res.json({ success: true });
  } catch (e) { res.status(400).json({ success: false, error: e.message }); }
});

app.post('/api/admin/users/:id/status', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['active','suspended'].includes(status)) return res.status(400).json({ success: false, error: 'Status tidak valid.' });
    await db.getPool().execute('UPDATE users SET status = ? WHERE id = ?', [status, req.params.id]);
    await auditLog(db, req.user.id, 'admin_user_status', { target: req.params.id, status }, getIp(req));
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal mengubah status.' }); }
});

// ============================================================
// ADMIN — ORDERS & TRANSACTIONS
// ============================================================
app.get('/api/admin/orders', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page  || '1'));
    const limit = Math.min(100, parseInt(req.query.limit || '30'));
    const where = req.query.status ? 'WHERE o.status = ?' : '';
    const params = req.query.status ? [req.query.status] : [];
    const total = (await db.queryOne(`SELECT COUNT(*) AS c FROM orders o ${where}`, params))?.c || 0;
    const data  = await db.query(
      `SELECT o.*, u.username, u.email FROM orders o LEFT JOIN users u ON u.id = o.user_id ${where} ORDER BY o.created_at DESC LIMIT ? OFFSET ?`,
      [...params, limit, (page - 1) * limit]
    );
    res.json({ success: true, data, total, page, limit });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal mengambil orders.' }); }
});

app.get('/api/admin/transactions', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const page  = Math.max(1, parseInt(req.query.page  || '1'));
    const limit = Math.min(100, parseInt(req.query.limit || '30'));
    const total = (await db.queryOne('SELECT COUNT(*) AS c FROM transactions'))?.c || 0;
    const data  = await db.query(
      'SELECT t.*, u.username FROM transactions t LEFT JOIN users u ON u.id = t.user_id ORDER BY t.created_at DESC LIMIT ? OFFSET ?',
      [limit, (page - 1) * limit]
    );
    res.json({ success: true, data, total, page, limit });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal mengambil transaksi.' }); }
});

// ============================================================
// ADMIN — SETTINGS
// ============================================================
app.get('/api/admin/settings', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const rows = await db.query('SELECT `key`, value FROM settings');
    const settings = Object.fromEntries(rows.map(r => [r.key, r.value]));
    res.json({ success: true, settings });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal memuat settings.' }); }
});

app.post('/api/admin/settings', authMiddleware, adminMiddleware, async (req, res) => {
  const ip = getIp(req);
  try {
    const allowed = ['markup_percent','site_name','site_tagline','maintenance_mode','auto_cancel_min'];
    for (const key of allowed) {
      if (req.body[key] !== undefined) await setSetting(db, key, String(req.body[key]));
    }
    await auditLog(db, req.user.id, 'admin_settings_update', req.body, ip);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ success: false, error: 'Gagal menyimpan settings.' }); }
});

app.get('/api/admin/provider-balance', authMiddleware, adminMiddleware, async (req, res) => {
  try { res.json({ success: true, ...await rumahotp.getBalance() }); }
  catch (e) { res.status(502).json({ success: false, error: 'Gagal mengambil saldo provider.' }); }
});

// ============================================================
// PUBLIC — site info
// ============================================================
app.get('/api/site-info', async (req, res) => {
  try {
    const rows = await db.query("SELECT `key`, value FROM settings WHERE `key` IN ('site_name','site_tagline','maintenance_mode')");
    const info = Object.fromEntries(rows.map(r => [r.key, r.value]));
    res.json({ success: true, ...info, logo: config.site.logoUrl, favicon: config.site.faviconUrl, support_email: config.site.supportEmail });
  } catch (e) { res.json({ success: true, site_name: config.site.name, site_tagline: config.site.tagline }); }
});

// ============================================================
// ERROR HANDLER
// ============================================================
app.use((req, res) => res.status(404).json({ success: false, error: 'Endpoint tidak ditemukan.' }));
app.use((err, req, res, next) => { log.error('Unhandled:', err.message); res.status(500).json({ success: false, error: 'Kesalahan server.' }); });

if (require.main === module) {
  app.listen(config.server.port, () => log.info(`Server running on port ${config.server.port}`));
}
module.exports = app;
