
require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const webpush = require('web-push');
const twilio = require('twilio');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'db.json');
const ENCRYPTED_DB_PATH = path.join(DATA_DIR, 'db.enc');
const DB_VERSION = 1;
const PBKDF2_ITERATIONS = 310000;
const MAX_BODY = '300kb';
const forceHttps = String(process.env.FORCE_HTTPS || '').toLowerCase() === 'true';

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: MAX_BODY }));
app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));
app.use('/app', express.static(path.join(__dirname, 'public', 'app')));

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function encryptionEnabled() {
  return Boolean(process.env.APP_ENCRYPTION_KEY && String(process.env.APP_ENCRYPTION_KEY).trim());
}

function normalizeSecret() {
  return String(process.env.APP_ENCRYPTION_KEY || '').trim();
}

function deriveDbKey(salt) {
  return crypto.pbkdf2Sync(normalizeSecret(), salt, PBKDF2_ITERATIONS, 32, 'sha256');
}

function encryptDbPayload(payload) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveDbKey(salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    version: DB_VERSION,
    algorithm: 'aes-256-gcm',
    kdf: 'pbkdf2-sha256',
    iterations: PBKDF2_ITERATIONS,
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ciphertext: ciphertext.toString('base64')
  }, null, 2);
}

function decryptDbPayload(envelopeText) {
  const envelope = JSON.parse(envelopeText);
  const salt = Buffer.from(envelope.salt, 'base64');
  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  const key = deriveDbKey(salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  return plaintext;
}

function buildEmptyDb() {
  return { clients: {} };
}

function loadDb() {
  ensureDataDir();
  if (encryptionEnabled()) {
    if (fs.existsSync(ENCRYPTED_DB_PATH)) {
      const decrypted = decryptDbPayload(fs.readFileSync(ENCRYPTED_DB_PATH, 'utf8'));
      return JSON.parse(decrypted);
    }
    if (fs.existsSync(DB_PATH)) {
      const legacyText = fs.readFileSync(DB_PATH, 'utf8');
      const parsed = JSON.parse(legacyText);
      fs.writeFileSync(ENCRYPTED_DB_PATH, encryptDbPayload(JSON.stringify(parsed)));
      fs.unlinkSync(DB_PATH);
      return parsed;
    }
    const seed = buildEmptyDb();
    fs.writeFileSync(ENCRYPTED_DB_PATH, encryptDbPayload(JSON.stringify(seed)));
    return seed;
  }
  if (!fs.existsSync(DB_PATH)) {
    const seed = buildEmptyDb();
    fs.writeFileSync(DB_PATH, JSON.stringify(seed, null, 2));
    return seed;
  }
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}

function saveDb(db) {
  ensureDataDir();
  const serialized = JSON.stringify(db, null, 2);
  if (encryptionEnabled()) {
    fs.writeFileSync(ENCRYPTED_DB_PATH, encryptDbPayload(serialized));
    if (fs.existsSync(DB_PATH)) fs.unlinkSync(DB_PATH);
    return;
  }
  fs.writeFileSync(DB_PATH, serialized);
}

function setSecurityHeaders(req, res, next) {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "manifest-src 'self'",
    "worker-src 'self'",
    "upgrade-insecure-requests"
  ].join('; ');
  res.setHeader('Content-Security-Policy', csp);
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
}

function redirectToHttps(req, res, next) {
  const proto = req.headers['x-forwarded-proto'];
  if (forceHttps && !req.secure && proto !== 'https') {
    return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
  }
  next();
}

const limiterBuckets = new Map();
function rateLimit({ windowMs, max, keyPrefix = 'global' }) {
  return (req, res, next) => {
    const key = `${keyPrefix}:${req.ip}`;
    const now = Date.now();
    const current = limiterBuckets.get(key) || { count: 0, resetAt: now + windowMs };
    if (now > current.resetAt) {
      current.count = 0;
      current.resetAt = now + windowMs;
    }
    current.count += 1;
    limiterBuckets.set(key, current);
    if (current.count > max) {
      return res.status(429).json({ error: 'Too many requests. Please try again shortly.' });
    }
    next();
  };
}

app.use(redirectToHttps);
app.use(setSecurityHeaders);

function getClient(db, clientId) {
  if (!db.clients[clientId]) {
    db.clients[clientId] = {
      items: [],
      settings: {
        pushEnabled: false,
        smsEnabled: false,
        smsPhone: '',
        reminderDays: [0, 1, 3],
        lastSmsSent: {},
        lastPushSent: {}
      },
      pushSubscription: null,
      updatedAt: new Date().toISOString()
    };
  }
  return db.clients[clientId];
}

function todayString() {
  return new Date().toISOString().split('T')[0];
}

function addDays(dateStr, days) {
  const date = new Date(dateStr + 'T12:00:00');
  date.setDate(date.getDate() + days);
  return date.toISOString().split('T')[0];
}

function addMonths(dateStr, months) {
  const date = new Date(dateStr + 'T12:00:00');
  const originalDay = date.getDate();
  date.setMonth(date.getMonth() + months);
  if (date.getDate() < originalDay) date.setDate(0);
  return date.toISOString().split('T')[0];
}

function addYears(dateStr, years) {
  const date = new Date(dateStr + 'T12:00:00');
  date.setFullYear(date.getFullYear() + years);
  return date.toISOString().split('T')[0];
}

function getNextDueDate(item) {
  if (!item.autoRenew) return item.dueDate;
  const today = new Date(todayString() + 'T12:00:00');
  let due = item.dueDate;
  let dueDate = new Date(due + 'T12:00:00');
  while (dueDate < today && item.autoRenew) {
    if (item.frequency === 'weekly') due = addDays(due, 7);
    else if (item.frequency === 'biweekly') due = addDays(due, 14);
    else if (item.frequency === 'monthly') due = addMonths(due, 1);
    else if (item.frequency === 'yearly') due = addYears(due, 1);
    else if (item.frequency === 'customDays') due = addDays(due, Number(item.customDays || 30));
    dueDate = new Date(due + 'T12:00:00');
  }
  return due;
}

function daysUntil(dateStr) {
  const today = new Date(todayString() + 'T12:00:00');
  const due = new Date(dateStr + 'T12:00:00');
  return Math.round((due - today) / 86400000);
}

function shouldSend(client, item, delta, channel) {
  const reminderDays = Array.isArray(client.settings.reminderDays) ? client.settings.reminderDays : [0, 1, 3];
  if (!reminderDays.includes(delta)) return false;
  const nextDate = getNextDueDate(item);
  const key = `${item.id}:${nextDate}:${delta}`;
  const sentMap = channel === 'sms' ? client.settings.lastSmsSent : client.settings.lastPushSent;
  return !sentMap[key];
}

function markSent(client, item, delta, channel) {
  const nextDate = getNextDueDate(item);
  const key = `${item.id}:${nextDate}:${delta}`;
  const mapName = channel === 'sms' ? 'lastSmsSent' : 'lastPushSent';
  client.settings[mapName][key] = new Date().toISOString();
}

function validateClientId(clientId) {
  return typeof clientId === 'string' && /^[a-f0-9-]{20,}$/.test(clientId);
}

function sanitizeSettings(settings) {
  const reminderDays = Array.isArray(settings?.reminderDays)
    ? settings.reminderDays.map(Number).filter(n => [0,1,3,7].includes(n))
    : [0,1,3];
  return {
    pushEnabled: Boolean(settings?.pushEnabled),
    smsEnabled: Boolean(settings?.smsEnabled),
    smsPhone: typeof settings?.smsPhone === 'string' ? settings.smsPhone.trim().slice(0, 30) : '',
    reminderDays: [...new Set(reminderDays)].sort((a,b) => b-a),
  };
}

function sanitizeItems(items) {
  return items.slice(0, 1000).map(item => ({
    id: String(item.id || crypto.randomUUID()).slice(0, 80),
    name: String(item.name || '').trim().slice(0, 120),
    category: String(item.category || '').trim().slice(0, 80),
    amount: Number(item.amount || 0),
    frequency: ['weekly', 'biweekly', 'monthly', 'yearly', 'customDays'].includes(item.frequency) ? item.frequency : 'monthly',
    customDays: Math.max(1, Math.min(3650, Number(item.customDays || 30))),
    dueDate: String(item.dueDate || '').slice(0, 20),
    autoRenew: Boolean(item.autoRenew),
    notes: String(item.notes || '').trim().slice(0, 300),
    createdAt: String(item.createdAt || new Date().toISOString()).slice(0, 40),
  }));
}

const haveVapid = process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY && process.env.VAPID_SUBJECT;
if (haveVapid) {
  webpush.setVapidDetails(process.env.VAPID_SUBJECT, process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);
}
const haveTwilio = process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN && process.env.TWILIO_FROM_NUMBER;
const twilioClient = haveTwilio ? twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN) : null;

app.get('/api/bootstrap', rateLimit({ windowMs: 60_000, max: 60, keyPrefix: 'bootstrap' }), (req, res) => {
  const clientId = String(req.query.clientId || '').trim();
  if (!validateClientId(clientId)) return res.status(400).json({ error: 'Valid clientId required' });
  const db = loadDb();
  const client = getClient(db, clientId);
  saveDb(db);
  res.json({
    items: client.items,
    settings: client.settings,
    pushConfigured: !!haveVapid,
    smsConfigured: !!haveTwilio,
    encryptionEnabled: encryptionEnabled(),
    vapidPublicKey: process.env.VAPID_PUBLIC_KEY || ''
  });
});

app.post('/api/items/sync', rateLimit({ windowMs: 60_000, max: 80, keyPrefix: 'items-sync' }), (req, res) => {
  const { clientId, items } = req.body || {};
  if (!validateClientId(clientId) || !Array.isArray(items)) return res.status(400).json({ error: 'clientId and items are required' });
  const db = loadDb();
  const client = getClient(db, clientId);
  client.items = sanitizeItems(items);
  client.updatedAt = new Date().toISOString();
  saveDb(db);
  res.json({ ok: true, encryptedAtRest: encryptionEnabled() });
});

app.post('/api/settings/sync', rateLimit({ windowMs: 60_000, max: 40, keyPrefix: 'settings-sync' }), (req, res) => {
  const { clientId, settings } = req.body || {};
  if (!validateClientId(clientId) || !settings) return res.status(400).json({ error: 'clientId and settings are required' });
  const db = loadDb();
  const client = getClient(db, clientId);
  client.settings = {
    ...client.settings,
    ...sanitizeSettings(settings),
    lastSmsSent: client.settings.lastSmsSent || {},
    lastPushSent: client.settings.lastPushSent || {}
  };
  client.updatedAt = new Date().toISOString();
  saveDb(db);
  res.json({ ok: true, encryptedAtRest: encryptionEnabled() });
});

app.post('/api/push/subscribe', rateLimit({ windowMs: 60_000, max: 20, keyPrefix: 'push-sub' }), (req, res) => {
  const { clientId, subscription } = req.body || {};
  if (!validateClientId(clientId) || !subscription) return res.status(400).json({ error: 'clientId and subscription are required' });
  const db = loadDb();
  const client = getClient(db, clientId);
  client.pushSubscription = subscription;
  client.settings.pushEnabled = true;
  client.updatedAt = new Date().toISOString();
  saveDb(db);
  res.json({ ok: true });
});

app.post('/api/push/test', rateLimit({ windowMs: 60_000, max: 10, keyPrefix: 'push-test' }), async (req, res) => {
  const { clientId } = req.body || {};
  if (!validateClientId(clientId)) return res.status(400).json({ error: 'Valid clientId required' });
  const db = loadDb();
  const client = getClient(db, clientId);
  if (!haveVapid) return res.status(400).json({ error: 'VAPID keys are not configured on the server.' });
  if (!client.pushSubscription) return res.status(400).json({ error: 'No push subscription saved for this device.' });
  try {
    await webpush.sendNotification(client.pushSubscription, JSON.stringify({
      title: 'BillShield test reminder',
      body: 'Push reminders are connected and ready.',
      url: process.env.APP_URL ? `${process.env.APP_URL.replace(/\/$/, '')}/app/` : '/app/'
    }));
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/sms/test', rateLimit({ windowMs: 60_000, max: 5, keyPrefix: 'sms-test' }), async (req, res) => {
  const { clientId } = req.body || {};
  if (!validateClientId(clientId)) return res.status(400).json({ error: 'Valid clientId required' });
  const db = loadDb();
  const client = getClient(db, clientId);
  if (!haveTwilio) return res.status(400).json({ error: 'Twilio is not configured on the server.' });
  if (!client.settings.smsPhone) return res.status(400).json({ error: 'No phone number saved for this client.' });
  try {
    const msg = await twilioClient.messages.create({
      to: client.settings.smsPhone,
      from: process.env.TWILIO_FROM_NUMBER,
      body: 'BillShield test SMS: your SMS alerts are connected and ready.'
    });
    res.json({ ok: true, sid: msg.sid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/reminders/run', rateLimit({ windowMs: 60_000, max: 30, keyPrefix: 'reminders' }), async (req, res) => {
  const secret = req.headers['x-cron-secret'] || req.query.secret;
  if (process.env.CRON_SECRET && secret !== process.env.CRON_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const db = loadDb();
  const summary = { clientsProcessed: 0, pushSent: 0, smsSent: 0, encryptedAtRest: encryptionEnabled(), errors: [] };

  for (const [clientId, client] of Object.entries(db.clients)) {
    summary.clientsProcessed += 1;
    const items = Array.isArray(client.items) ? client.items : [];
    for (const item of items) {
      const nextDate = getNextDueDate(item);
      const delta = daysUntil(nextDate);
      if (delta < 0) continue;
      const label = delta === 0 ? 'today' : `in ${delta} day${delta === 1 ? '' : 's'}`;
      const message = `${item.name} for $${Number(item.amount || 0).toFixed(2)} is due ${label} (${nextDate}).`;

      if (client.settings.pushEnabled && client.pushSubscription && haveVapid && shouldSend(client, item, delta, 'push')) {
        try {
          await webpush.sendNotification(client.pushSubscription, JSON.stringify({
            title: 'Payment reminder',
            body: message,
            url: process.env.APP_URL ? `${process.env.APP_URL.replace(/\/$/, '')}/app/` : '/app/'
          }));
          markSent(client, item, delta, 'push');
          summary.pushSent += 1;
        } catch (error) {
          summary.errors.push(`Push failed for ${clientId}/${item.name}: ${error.message}`);
        }
      }

      if (client.settings.smsEnabled && client.settings.smsPhone && haveTwilio && shouldSend(client, item, delta, 'sms')) {
        try {
          await twilioClient.messages.create({
            to: client.settings.smsPhone,
            from: process.env.TWILIO_FROM_NUMBER,
            body: `BillShield: ${message}`
          });
          markSent(client, item, delta, 'sms');
          summary.smsSent += 1;
        } catch (error) {
          summary.errors.push(`SMS failed for ${clientId}/${item.name}: ${error.message}`);
        }
      }
    }
  }

  saveDb(db);
  res.json(summary);
});

app.get('/health', (req, res) => {
  res.json({ ok: true, app: 'BillShield', encryptionEnabled: encryptionEnabled(), pushConfigured: !!haveVapid, smsConfigured: !!haveTwilio });
});

app.get('/', (req, res) => {
  const checkoutUrl = process.env.CHECKOUT_URL && String(process.env.CHECKOUT_URL).trim() ? process.env.CHECKOUT_URL : '/app/';
  const html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8')
    .replaceAll('{{CHECKOUT_URL}}', checkoutUrl);
  res.type('html').send(html);
});

app.get('/app/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`BillShield launch kit listening on http://localhost:${PORT}`);
  if (encryptionEnabled()) {
    console.log('Database encryption at rest is enabled (AES-256-GCM).');
  } else {
    console.log('Warning: APP_ENCRYPTION_KEY is not set. Database encryption is disabled.');
  }
});
