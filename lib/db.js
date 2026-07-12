'use strict';
const mysql = require('mysql2/promise');
const config = require('../config');

let pool = null;

function getPool() {
  if (!pool) {
    pool = mysql.createPool({
      host:            config.database.host,
      port:            config.database.port,
      database:        config.database.database,
      user:            config.database.user,
      password:        config.database.password,
      waitForConnections: true,
      connectionLimit: config.database.connectionLimit, // kecil untuk serverless
      queueLimit:      0,
      enableKeepAlive: true,
      keepAliveInitialDelay: 0,
      timezone:        '+07:00', // WIB
    });
  }
  return pool;
}

/** Jalankan single query */
async function query(sql, params = []) {
  const db = getPool();
  const [rows] = await db.execute(sql, params);
  return rows;
}

/** Ambil satu baris */
async function queryOne(sql, params = []) {
  const rows = await query(sql, params);
  return rows[0] || null;
}

/** Transaksi — callback menerima (conn) => ... */
async function transaction(callback) {
  const conn = await getPool().getConnection();
  try {
    await conn.beginTransaction();
    const result = await callback(conn);
    await conn.commit();
    return result;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

module.exports = { getPool, query, queryOne, transaction };
