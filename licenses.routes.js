import express from 'express';
import { openDb } from './db.js';
import { v4 as uuidv4 } from 'uuid';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import CryptoJS from 'crypto-js';
import crypto from 'crypto';

// Load environment variables from .env
import dotenv from 'dotenv';
dotenv.config();

const router = express.Router();

// List all licenses
router.get('/', async (req, res) => {
  const db = await openDb();
  const licenses = await db.all('SELECT * FROM licenses');
  // Add a flag if encrypted_config exists for each license
  licenses.forEach(lic => {
    lic.hasEncryptedConfig = !!lic.encrypted_config;
  });
  res.render('licenses', { licenses });
});
// Download encrypted config for a license
router.get('/download-config/:uuid', async (req, res) => {
  const db = await openDb();
  const license = await db.get('SELECT * FROM licenses WHERE uuid = ?', req.params.uuid);
  if (!license || !license.encrypted_config) {
    return res.status(404).send('Encrypted config not found');
  }
  res.setHeader('Content-disposition', `attachment; filename=config-${license.uuid}.json.enc`);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.send(license.encrypted_config);
});

// Download encrypted client certificate
router.get('/download-cert/:uuid', async (req, res, next) => {
  const certDir = path.join(process.cwd(), 'client-certs');
  const certFileEnc = path.join(certDir, `client-cert-${req.params.uuid}.pem.enc`);
  if (!fs.existsSync(certFileEnc)) {
    return res.status(404).send('Encrypted certificate not found');
  }
  res.setHeader('Content-disposition', `attachment; filename=client-cert-${req.params.uuid}.pem.enc`);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.send(fs.readFileSync(certFileEnc, 'utf8'));
});

// Download encrypted client private key
router.get('/download-key/:uuid', async (req, res, next) => {
  const certDir = path.join(process.cwd(), 'client-certs');
  const keyFileEnc = path.join(certDir, `client-key-${req.params.uuid}.pem.enc`);
  if (!fs.existsSync(keyFileEnc)) {
    return res.status(404).send('Encrypted private key not found');
  }
  res.setHeader('Content-disposition', `attachment; filename=client-key-${req.params.uuid}.pem.enc`);
  res.setHeader('Content-Type', 'application/octet-stream');
  res.send(fs.readFileSync(keyFileEnc, 'utf8'));
});

// Edit license form
router.get('/edit/:uuid', async (req, res) => {
  const db = await openDb();
  const license = await db.get('SELECT * FROM licenses WHERE uuid = ?', req.params.uuid);
  res.render('editLicense', { license });
});

// Update license
router.post('/edit/:uuid', async (req, res) => {
  const db = await openDb();
  const { company_name, cnpj, phone, email, valid_until } = req.body;
  await db.run(
    'UPDATE licenses SET company_name=?, cnpj=?, phone=?, email=?, valid_until=? WHERE uuid=?',
    company_name, cnpj, phone, email, valid_until, req.params.uuid
  );
  res.redirect('/licenses');
});

// Delete all licenses
router.post('/delete-all', async (req, res) => {
  const db = await openDb();
  await db.run('DELETE FROM licenses');
  res.redirect('/licenses');
});

// Delete a specific license by UUID
router.post('/delete/:uuid', async (req, res) => {
  const db = await openDb();
  await db.run('DELETE FROM licenses WHERE uuid = ?', req.params.uuid);
  res.redirect('/licenses');
});

// Add new license form
router.get('/add', (req, res) => {
  // valid_until is today + 30 days
  const now = new Date();
  const valid_until = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 16); // yyyy-MM-ddTHH:mm
  res.render('editLicense', { license: { valid_until }, isNew: true });
});

// Add new license
router.post('/add', async (req, res, next) => {
    const db = await openDb();
    const { company_name, cnpj, phone, email } = req.body;
    const uuid = uuidv4();
    const api_key = crypto.randomBytes(24).toString('hex');
    const created_at = new Date().toISOString();
    const valid_until = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();

    // Ensure client-certs directory exists
    const certDir = path.join(process.cwd(), 'client-certs');
    if (!fs.existsSync(certDir)) {
        fs.mkdirSync(certDir);
    }

    // The cert and key will be named uniquely by uuid
    const keyFile = path.join(certDir, `client-key-${uuid}.pem`);
    const certFile = path.join(certDir, `client-cert-${uuid}.pem`);
    const keyFileEnc = path.join(certDir, `client-key-${uuid}.pem.enc`);
    const certFileEnc = path.join(certDir, `client-cert-${uuid}.pem.enc`);
    try {
        // Call the shell script to generate the cert and key
        execSync(`bash ./utils/generate-client-cert.sh ${uuid} "${company_name || uuid}"`);
        const client_cert = fs.readFileSync(certFile, 'utf8');
        const client_key = fs.readFileSync(keyFile, 'utf8');
        // Encrypt and save encrypted versions
        const encCert = CryptoJS.AES.encrypt(client_cert, uuid).toString();
        const encKey = CryptoJS.AES.encrypt(client_key, uuid).toString();
        fs.writeFileSync(certFileEnc, encCert, 'utf8');
        fs.writeFileSync(keyFileEnc, encKey, 'utf8');
        // Store both plaintext and encrypted cert in the database
        await db.run(
          'INSERT INTO licenses (uuid, company_name, cnpj, phone, email, created_at, valid_until, client_cert, encrypted_client_cert, api_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
          uuid, company_name, cnpj, phone, email, created_at, valid_until, client_cert, encCert, api_key
        );

        const config = {
          uuid,
          apiKey: api_key,
          clientCert: `client-cert-${uuid}.pem`,
          clientKey: `client-key-${uuid}.pem`,
          serverCA: 'server-cert.pem',
          licenseFile: 'client-license.json',
          licenseServerUrl: process.env.LICENSE_SERVER_URL || 'https://localhost:8443',
          validateEndpoint: '/api/validate',
          licenseEndpoint: '/license',
          retryIntervalMs: 10000,
          maxAttempts: 3
        };
        const encryptedConfig = CryptoJS.AES.encrypt(JSON.stringify(config), uuid).toString();

        // Optionally, store encryptedConfig in the database, or make it available for download in the license view.
        await db.run('UPDATE licenses SET encrypted_config = ? WHERE uuid = ?', encryptedConfig, uuid);

        // Optionally, keep or clean up CSR and key files
        res.redirect('/licenses');
    } catch (e) {
        next(new Error('Error generating client certificate: ' + e.message));
    }
});

export default router;
