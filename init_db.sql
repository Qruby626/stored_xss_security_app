-- ============================================================
-- Stored XSS Security Research Platform
-- Database Initialization Script
-- ============================================================

CREATE DATABASE IF NOT EXISTS stored_xss_security
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE stored_xss_security;

-- SQLAlchemy akan membuat tabel otomatis via db.create_all()
-- Script ini hanya untuk memastikan database ada.
