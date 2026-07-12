-- =============================================
-- OTP STORE — SCHEMA MARIADB
-- Jalankan sekali: mysql -u root -p otp_store < schema.sql
-- =============================================

CREATE DATABASE IF NOT EXISTS otp_store
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE otp_store;

-- ── USERS ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username        VARCHAR(50)  NOT NULL UNIQUE,
  email           VARCHAR(100) NOT NULL UNIQUE,
  password_hash   VARCHAR(255) NOT NULL,
  telegram_chat_id VARCHAR(50) NULL,
  telegram_username VARCHAR(100) NULL,
  balance         DECIMAL(15,2) NOT NULL DEFAULT 0.00,
  role            ENUM('user','admin') NOT NULL DEFAULT 'user',
  status          ENUM('active','suspended') NOT NULL DEFAULT 'active',
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  INDEX idx_email (email),
  INDEX idx_role  (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── TELEGRAM LINK TOKENS (tautan akun Telegram) ──
CREATE TABLE IF NOT EXISTS telegram_link_tokens (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NOT NULL,
  token      VARCHAR(32) NOT NULL UNIQUE,
  expires_at TIMESTAMP NOT NULL,
  used       TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_token (token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── LOGIN VERIFICATIONS (kode 6-digit via Telegram) ──
CREATE TABLE IF NOT EXISTS login_verifications (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NOT NULL,
  code       VARCHAR(10)  NOT NULL,
  attempts   TINYINT UNSIGNED NOT NULL DEFAULT 0,
  expires_at TIMESTAMP NOT NULL,
  used       TINYINT(1) NOT NULL DEFAULT 0,
  ip_address VARCHAR(45) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_used (user_id, used)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── ORDERS (pesanan nomor virtual) ────────────
CREATE TABLE IF NOT EXISTS orders (
  id               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id          INT UNSIGNED NOT NULL,
  rumahotp_order_id VARCHAR(100) NULL,
  service_id       VARCHAR(100) NOT NULL,
  service_name     VARCHAR(100) NULL,
  country          VARCHAR(20)  NOT NULL,
  country_name     VARCHAR(100) NULL,
  provider_id      VARCHAR(100) NULL,
  operator_id      VARCHAR(100) NULL,
  number_id        VARCHAR(100) NULL,
  phone_number     VARCHAR(30)  NULL,
  otp_code         VARCHAR(30)  NULL,
  otp_message      TEXT         NULL,
  base_price       DECIMAL(15,2) NOT NULL DEFAULT 0.00,
  price            DECIMAL(15,2) NOT NULL DEFAULT 0.00,
  status           ENUM('pending_payment','paid','number_issued','otp_received','completed','cancelled','expired')
                   NOT NULL DEFAULT 'pending_payment',
  expires_at       TIMESTAMP    NULL,
  created_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_status (user_id, status),
  INDEX idx_rumahotp_order (rumahotp_order_id),
  INDEX idx_status_expires (status, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── TRANSACTIONS (pembayaran Pakasir) ─────────
CREATE TABLE IF NOT EXISTS transactions (
  id                  INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  order_id            INT UNSIGNED NOT NULL,
  user_id             INT UNSIGNED NOT NULL,
  pakasir_order_id    VARCHAR(100) NOT NULL UNIQUE,
  amount              DECIMAL(15,2) NOT NULL,
  status              ENUM('pending','success','failed','cancelled') NOT NULL DEFAULT 'pending',
  payment_method      VARCHAR(50)  NULL,
  qr_string           TEXT         NULL,
  expired_at          TIMESTAMP    NULL,
  raw_webhook_payload JSON         NULL,
  webhook_received    TINYINT(1)   NOT NULL DEFAULT 0,
  processed           TINYINT(1)   NOT NULL DEFAULT 0,
  created_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (order_id)  REFERENCES orders(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id)   REFERENCES users(id)  ON DELETE CASCADE,
  INDEX idx_pakasir_order (pakasir_order_id),
  INDEX idx_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── BALANCE LOGS (riwayat saldo) ──────────────
CREATE TABLE IF NOT EXISTS balance_logs (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id     INT UNSIGNED NOT NULL,
  type        ENUM('credit','debit') NOT NULL,
  amount      DECIMAL(15,2) NOT NULL,
  balance_before DECIMAL(15,2) NOT NULL,
  balance_after  DECIMAL(15,2) NOT NULL,
  reference_type ENUM('deposit','order','refund','admin_adjust') NOT NULL,
  reference_id   INT UNSIGNED NULL,
  note        VARCHAR(255) NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_type (user_id, type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── SETTINGS (konfigurasi admin) ──────────────
CREATE TABLE IF NOT EXISTS settings (
  `key`       VARCHAR(100) NOT NULL PRIMARY KEY,
  value       TEXT         NOT NULL,
  updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Nilai default settings
INSERT IGNORE INTO settings (`key`, value) VALUES
  ('markup_percent',  '15'),
  ('site_name',       'ReceOTP'),
  ('site_tagline',    'Nomor Virtual OTP Instan, Aman, Murah'),
  ('maintenance_mode','0'),
  ('auto_cancel_min', '20');

-- ── AUDIT LOGS ────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id     INT UNSIGNED NULL,
  action      VARCHAR(100) NOT NULL,
  details     JSON         NULL,
  ip_address  VARCHAR(45)  NULL,
  status      ENUM('success','failed') NOT NULL DEFAULT 'success',
  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_user   (user_id),
  INDEX idx_action (action),
  INDEX idx_created(created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
