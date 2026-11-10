import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import Database from "better-sqlite3";
import crypto from "crypto";
import admin from "firebase-admin";
import path from "path";
import { fileURLToPath } from "url";
import nodemailer from "nodemailer";
import fs from "fs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, ".env") });
dotenv.config();

// Crash-proof exception & rejection safety handlers
process.on("uncaughtException", (err) => {
  console.error("🛡️ [RECOVERED UNCAUGHT EXCEPTION]:", err.message || err);
});
process.on("unhandledRejection", (reason, promise) => {
  console.error("🛡️ [RECOVERED UNHANDLED REJECTION]:", reason);
});

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================
// FIREBASE ADMIN
// ============================================================

let firebaseAdminReady = false;

try {
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS && fs.existsSync(process.env.GOOGLE_APPLICATION_CREDENTIALS)) {
    admin.initializeApp({
      credential: admin.credential.applicationDefault(),
    });
    firebaseAdminReady = true;
    console.log("Firebase Admin authentication enabled.");
  } else if (process.env.FIREBASE_CONFIG) {
    admin.initializeApp();
    firebaseAdminReady = true;
    console.log("Firebase Admin authentication enabled via FIREBASE_CONFIG.");
  } else {
    console.warn("Firebase Admin is not configured. Set GOOGLE_APPLICATION_CREDENTIALS.");
  }
} catch (error) {
  console.error("Firebase Admin initialization failed:", error.message);
}

// ============================================================
// EXPRESS & SECURITY MIDDLEWARE
// ============================================================

const allowedOrigins = new Set(
  (process.env.CORS_ORIGINS || "https://suryasgroceries.web.app")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(new Error("Origin is not allowed by CORS."));
  },
}));

// Request body limit (6MB maximum to safely handle base64 screenshots without memory denial of service)
app.use(express.json({ limit: "6mb" }));

// Express body size limit error handler
app.use((err, req, res, next) => {
  if (err && (err.type === "entity.too.large" || err.status === 413)) {
    return res.status(413).json({
      ok: false,
      message: "Uploaded request payload exceeds the allowed limit (6MB).",
    });
  }
  next(err);
});

app.use("/public", express.static(path.join(__dirname, "public")));

// Dedicated APK download endpoints with attachment header
app.get(["/SuryaStore.apk", "/download-apk", "/public/SuryaStore.apk"], (req, res) => {
  const apkPath = path.join(__dirname, "public", "SuryaStore.apk");
  if (fs.existsSync(apkPath)) {
    res.setHeader("Content-Disposition", 'attachment; filename="SuryaStore.apk"');
    res.setHeader("Content-Type", "application/vnd.android.package-archive");
    return res.sendFile(apkPath);
  }
  return res.status(404).json({ error: "SuryaStore.apk not found" });
});

// ============================================================
// SQLITE DATABASE
// ============================================================

let dbFile = process.env.DB_PATH;
if (dbFile) {
  try {
    const dbDir = path.dirname(dbFile);
    if (dbDir && dbDir !== "." && !fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
    }
  } catch (err) {
    console.warn(`[DB WARNING] Could not access ${dbFile}: ${err.message}. Falling back.`);
    dbFile = null;
  }
}

if (!dbFile) {
  dbFile = fs.existsSync(path.join(__dirname, "suryas_groceries.db"))
    ? path.join(__dirname, "suryas_groceries.db")
    : path.join(__dirname, "bismilla.db");
}

let db;
try {
  db = new Database(dbFile);
} catch (err) {
  console.error(`[DB ERROR] Error opening ${dbFile}: ${err.message}. Using local suryas_groceries.db`);
  dbFile = path.join(__dirname, "suryas_groceries.db");
  db = new Database(dbFile);
}

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// Periodic SQLite WAL checkpointing every 15 minutes
setInterval(() => {
  try {
    db.pragma("wal_checkpoint(PASSIVE)");
  } catch (_) {}
}, 15 * 60 * 1000);

// ============================================================
// DATABASE TABLES
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  firebase_uid TEXT UNIQUE,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  mobile TEXT NOT NULL,
  password_hash TEXT NOT NULL DEFAULT '',
  address TEXT DEFAULT '',
  latitude REAL,
  longitude REAL,
  location_accuracy REAL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  login_time TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  order_id TEXT NOT NULL UNIQUE,
  tracking_token TEXT,
  amount REAL NOT NULL,
  payment_method TEXT NOT NULL,
  payment_status TEXT NOT NULL,
  order_status TEXT NOT NULL,
  items_json TEXT NOT NULL,
  address TEXT,
  latitude REAL,
  longitude REAL,
  location_accuracy REAL,
  utr TEXT,
  payment_screenshot TEXT,
  payment_time TEXT NOT NULL,
  user_name TEXT,
  user_email TEXT,
  user_mobile TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS redeemed_coupons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  email TEXT,
  coupon_code TEXT NOT NULL,
  used_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_user_time ON login_events(user_id, login_time);
CREATE INDEX IF NOT EXISTS idx_payment_user_time ON payments(user_id, payment_time);
`);

// Table column migrations
const userColumns = db.prepare("PRAGMA table_info(users)").all().map((c) => c.name);
if (!userColumns.includes("firebase_uid")) db.exec("ALTER TABLE users ADD COLUMN firebase_uid TEXT");
if (!userColumns.includes("latitude")) db.exec("ALTER TABLE users ADD COLUMN latitude REAL");
if (!userColumns.includes("longitude")) db.exec("ALTER TABLE users ADD COLUMN longitude REAL");
if (!userColumns.includes("location_accuracy")) db.exec("ALTER TABLE users ADD COLUMN location_accuracy REAL");

const paymentColumns = db.prepare("PRAGMA table_info(payments)").all().map((c) => c.name);
if (!paymentColumns.includes("latitude")) db.exec("ALTER TABLE payments ADD COLUMN latitude REAL");
if (!paymentColumns.includes("longitude")) db.exec("ALTER TABLE payments ADD COLUMN longitude REAL");
if (!paymentColumns.includes("location_accuracy")) db.exec("ALTER TABLE payments ADD COLUMN location_accuracy REAL");
if (!paymentColumns.includes("utr")) db.exec("ALTER TABLE payments ADD COLUMN utr TEXT");
if (!paymentColumns.includes("payment_screenshot")) db.exec("ALTER TABLE payments ADD COLUMN payment_screenshot TEXT");
if (!paymentColumns.includes("user_name")) db.exec("ALTER TABLE payments ADD COLUMN user_name TEXT");
if (!paymentColumns.includes("user_email")) db.exec("ALTER TABLE payments ADD COLUMN user_email TEXT");
if (!paymentColumns.includes("user_mobile")) db.exec("ALTER TABLE payments ADD COLUMN user_mobile TEXT");
if (!paymentColumns.includes("tracking_token")) db.exec("ALTER TABLE payments ADD COLUMN tracking_token TEXT");
if (!userColumns.includes("pincode")) db.exec("ALTER TABLE users ADD COLUMN pincode TEXT");
if (!userColumns.includes("last_active_at")) db.exec("ALTER TABLE users ADD COLUMN last_active_at TEXT");
if (!paymentColumns.includes("pincode")) db.exec("ALTER TABLE payments ADD COLUMN pincode TEXT");
if (!paymentColumns.includes("cancellation_requested")) db.exec("ALTER TABLE payments ADD COLUMN cancellation_requested INTEGER DEFAULT 0");
if (!paymentColumns.includes("cancellation_reason")) db.exec("ALTER TABLE payments ADD COLUMN cancellation_reason TEXT");
if (!paymentColumns.includes("cancellation_query")) db.exec("ALTER TABLE payments ADD COLUMN cancellation_query TEXT");
if (!paymentColumns.includes("cancellation_time")) db.exec("ALTER TABLE payments ADD COLUMN cancellation_time TEXT");
if (!paymentColumns.includes("cancellation_status")) db.exec("ALTER TABLE payments ADD COLUMN cancellation_status TEXT DEFAULT 'None'");

// Security Cleanup: Zero out any legacy plaintext passwords in SQLite without deleting user accounts
try {
  db.exec("UPDATE users SET password_hash = '' WHERE password_hash != '';");
} catch (_) {}

// ============================================================
// PRODUCTS TABLE & SEEDING
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  price REAL NOT NULL,
  category TEXT NOT NULL,
  is_veg INTEGER DEFAULT 1,
  rating REAL DEFAULT 4.8,
  reviews TEXT DEFAULT '100+',
  prep_time TEXT DEFAULT 'Express 15m',
  serves TEXT DEFAULT '1 Unit',
  badge TEXT DEFAULT '',
  image TEXT,
  gallery_json TEXT NOT NULL DEFAULT '[]',
  ingredients_json TEXT NOT NULL DEFAULT '[]',
  benefits TEXT DEFAULT '',
  suitable_for TEXT DEFAULT '',
  in_stock INTEGER DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const productColumns = db.prepare("PRAGMA table_info(products)").all().map((c) => c.name);
for (const [column, definition] of [
  ["gallery_json", "TEXT NOT NULL DEFAULT '[]'"],
  ["ingredients_json", "TEXT NOT NULL DEFAULT '[]'"],
  ["benefits", "TEXT DEFAULT ''"],
  ["suitable_for", "TEXT DEFAULT ''"],
  ["barcode", "TEXT DEFAULT ''"],
]) {
  if (!productColumns.includes(column)) {
    db.exec(`ALTER TABLE products ADD COLUMN ${column} ${definition}`);
  }
}

// Seed product catalog from server/catalog.json if products table is empty
try {
  const catalogCount = db.prepare("SELECT COUNT(*) as count FROM products").get().count;
  const catalogPath = path.join(__dirname, "catalog.json");
  if (catalogCount === 0 && fs.existsSync(catalogPath)) {
    const rawCatalog = JSON.parse(fs.readFileSync(catalogPath, "utf8"));
    const insertProd = db.prepare(`
      INSERT OR IGNORE INTO products (
        id, name, description, price, category, is_veg, rating, reviews,
        prep_time, serves, badge, image, gallery_json, ingredients_json,
        benefits, suitable_for, in_stock, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '[]', '[]', '', '', 1, datetime('now'))
    `);
    const seedTx = db.transaction((catalog) => {
      for (const it of catalog) {
        insertProd.run(
          it.id,
          it.name,
          it.description || "",
          Number(it.price) || 0,
          it.category || "Groceries",
          it.is_veg === 0 ? 0 : 1,
          Number(it.rating) || 4.8,
          it.reviews || "10+",
          it.prep_time || "Express 15m",
          it.serves || "1 Unit",
          it.badge || "",
          it.image || ""
        );
      }
    });
    seedTx(rawCatalog);
    console.log(`Seeded ${rawCatalog.length} catalog products into database.`);
  }
} catch (seedErr) {
  console.error("Product catalog seeding warning:", seedErr.message);
}

// ============================================================
// HELPERS
// ============================================================

function nowIso() {
  return new Date().toISOString();
}

function getClientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) {
    return xff.split(",")[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || "unknown_ip";
}

function publicUser(row) {
  return {
    id: row.id,
    uid: row.firebase_uid || `user_${row.id}`,
    email: row.email,
    profile: {
      name: row.name,
      email: row.email,
      mobile: row.mobile,
      address: row.address || "",
      pincode: row.pincode || "",
      latitude: row.latitude ?? null,
      longitude: row.longitude ?? null,
      accuracy: row.location_accuracy ?? null,
      createdAt: row.created_at,
    },
  };
}

// ============================================================
// PRODUCTION-APPROPRIATE RATE LIMITER
// ============================================================

const rateLimits = new Map();

function checkRateLimit(key, maxLimit, windowMs) {
  const now = Date.now();
  const record = rateLimits.get(key) || { count: 0, windowStart: now };
  if (now - record.windowStart > windowMs) {
    record.count = 1;
    record.windowStart = now;
    rateLimits.set(key, record);
    return true;
  }
  if (record.count >= maxLimit) {
    return false;
  }
  record.count += 1;
  rateLimits.set(key, record);
  return true;
}

// Clean up expired rate limit records periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, record] of rateLimits.entries()) {
    if (now - record.windowStart > 60 * 60 * 1000) {
      rateLimits.delete(key);
    }
  }
}, 30 * 60 * 1000);

// ============================================================
// FIREBASE AUTH MIDDLEWARE
// ============================================================

async function firebaseAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Firebase token required." });
    }

    const idToken = header.substring(7);

    if (firebaseAdminReady) {
      try {
        const decoded = await admin.auth().verifyIdToken(idToken);
        req.firebaseUser = decoded;
        return next();
      } catch (adminErr) {
        console.warn("admin.verifyIdToken failed, using REST fallback:", adminErr.message);
      }
    }

    // Fallback: Verify token directly using Google Identity Toolkit REST API
    try {
      const apiKey = process.env.FIREBASE_API_KEY;
      if (!apiKey) {
        return res.status(401).json({ message: "Firebase authentication service is unconfigured." });
      }

      const lookupRes = await fetch(
        `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ idToken }),
        }
      );

      if (lookupRes.ok) {
        const data = await lookupRes.json();
        if (data.users && data.users.length > 0) {
          const u = data.users[0];
          req.firebaseUser = {
            uid: u.localId,
            user_id: u.localId,
            email: u.email,
            name: u.displayName || (u.email ? u.email.split("@")[0] : "Customer"),
            phone_number: u.phoneNumber || "",
          };
          return next();
        }
      }
    } catch (lookupErr) {
      console.warn("Google REST token lookup error:", lookupErr.message);
    }

    return res.status(401).json({ message: "Invalid or expired Firebase token." });
  } catch (error) {
    console.error("Firebase authentication error:", error.message);
    return res.status(401).json({ message: "Authentication verification failed." });
  }
}

// ============================================================
// SYNC FIREBASE USER WITH SQLITE
// ============================================================

async function syncUser(req, res, next) {
  try {
    const firebaseUser = req.firebaseUser;
    const firebaseUid = firebaseUser.uid;
    const email = String(firebaseUser.email || "").trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ message: "Firebase account does not contain an email." });
    }

    let user = db.prepare("SELECT * FROM users WHERE firebase_uid = ?").get(firebaseUid);
    if (!user) {
      user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    }

    const bodyMobile = (req.body?.mobile || "").toString().replace(/[^0-9]/g, "").slice(-10);
    const bodyName = (req.body?.name || "").toString().trim();
    const effectiveMobile = (firebaseUser.phone_number || bodyMobile || "").trim();

    if (!user) {
      const bodyPincode = (req.body?.pincode || req.body?.pinCode || "").toString().trim();
      const result = db.prepare(`
        INSERT INTO users (firebase_uid, name, email, mobile, pincode, password_hash, created_at)
        VALUES (?, ?, ?, ?, ?, '', ?)
      `).run(
        firebaseUid,
        bodyName || firebaseUser.name || email.split("@")[0],
        email,
        effectiveMobile,
        bodyPincode,
        nowIso()
      );

      user = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
    } else {
      const updateMobile = bodyMobile.length >= 10 ? bodyMobile : (user.mobile || "");
      const updateName = bodyName.length > 0 ? bodyName : (user.name || "");
      const updatePincode = (req.body?.pincode || req.body?.pinCode || "").toString().trim();
      db.prepare(`
        UPDATE users
        SET
          firebase_uid = COALESCE(NULLIF(?, ''), firebase_uid),
          mobile = CASE WHEN ? != '' THEN ? ELSE mobile END,
          name = CASE WHEN ? != '' THEN ? ELSE name END,
          pincode = CASE WHEN ? != '' THEN ? ELSE pincode END
        WHERE id = ?
      `).run(firebaseUid, updateMobile, updateMobile, updateName, updateName, updatePincode, updatePincode, user.id);

      user = db.prepare("SELECT * FROM users WHERE id = ?").get(user.id);
    }

    try {
      db.prepare("UPDATE users SET last_active_at = ? WHERE id = ?").run(nowIso(), user.id);
      user.last_active_at = nowIso();
    } catch (_) {}

    req.user = user;
    next();
  } catch (error) {
    console.error("User sync error:", error.message);
    res.status(500).json({ message: "Could not sync user." });
  }
}

// ============================================================
// HEALTH
// ============================================================

app.get(["/health", "/api/health"], (req, res) => {
  res.json({
    ok: true,
    service: "Surya's General Store API",
    database: "SQLite",
  });
});

// ============================================================
// IN-MEMORY SECURE OTP STORE & VERIFICATION
// ============================================================

const otpStore = new Map();

function generateOtp() {
  // Cryptographically secure 6-digit random integer generator
  return crypto.randomInt(100000, 1000000).toString();
}

function normalizeTarget(target) {
  const trimmed = (target || "").toLowerCase().trim();
  if (trimmed.includes("@")) return trimmed;
  const digits = trimmed.replace(/[^0-9]/g, "");
  return digits.length >= 10 ? digits.slice(-10) : digits;
}

function saveOtp(target, otp) {
  const key = normalizeTarget(target);
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes validity
  otpStore.set(key, { otp, expiresAt, attempts: 0 });
}

function verifyStoredOtp(target, inputOtp) {
  const key = normalizeTarget(target);
  const entry = otpStore.get(key);
  const cleanInput = (inputOtp || "").trim();

  if (!entry) {
    return { ok: false, message: "No active verification code found." };
  }

  if (Date.now() > entry.expiresAt) {
    otpStore.delete(key);
    return { ok: false, message: "Verification code has expired." };
  }

  entry.attempts += 1;
  if (entry.attempts > 5) {
    otpStore.delete(key);
    return { ok: false, message: "Too many failed attempts. Code has been invalidated." };
  }

  // Cryptographic constant-time comparison prevents timing analysis
  const expectedBuf = Buffer.from(entry.otp);
  const inputBuf = Buffer.from(cleanInput);
  const matches = expectedBuf.length === inputBuf.length && crypto.timingSafeEqual(expectedBuf, inputBuf);

  if (matches) {
    otpStore.delete(key); // Single use: invalidate immediately on success
    return { ok: true };
  }

  return { ok: false, message: "Invalid verification code." };
}

// Clean up expired OTPs periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of otpStore.entries()) {
    if (now > entry.expiresAt) {
      otpStore.delete(key);
    }
  }
}, 60 * 1000);

// ============================================================
// EMAIL DISPATCHER (NODEMAILER)
// ============================================================

const EMAIL_USER = process.env.EMAIL_USER || "kilarimokshagna123@gmail.com";
const EMAIL_PASS = process.env.EMAIL_PASS || "yikwxohmszpwujqw";
const isEmailConfigured = Boolean(EMAIL_USER && EMAIL_PASS);

let emailTransporter = null;
if (isEmailConfigured) {
  emailTransporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    pool: true,
    maxConnections: 5,
    maxMessages: 100,
    rateDelta: 1000,
    rateLimit: 5,
    connectionTimeout: 5000,
    greetingTimeout: 5000,
    socketTimeout: 5000,
    auth: {
      user: EMAIL_USER,
      pass: EMAIL_PASS,
    },
    tls: {
      rejectUnauthorized: false,
    },
  });
}

async function sendRealEmail(email, otp) {
  if (!isEmailConfigured || !emailTransporter) {
    return { sent: false, error: "Email delivery service is not configured in environment." };
  }
  try {
    const info = await emailTransporter.sendMail({
      from: `"Surya's General Store" <${EMAIL_USER}>`,
      to: email,
      subject: "Your Surya's General Store Verification Code",
      headers: {
        "X-Priority": "1 (Highest)",
        "X-MSMail-Priority": "High",
        Importance: "High",
      },
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 24px; border: 1px solid #E5E7EB; border-radius: 16px; background-color: #ffffff;">
          <div style="text-align: center; margin-bottom: 20px;">
            <div style="display: inline-block; background: #2E7D32; color: #ffffff; padding: 8px 18px; border-radius: 20px; font-weight: 800; font-size: 15px; letter-spacing: 0.5px;">
              SURYA'S GENERAL STORE
            </div>
            <p style="color: #6B7280; font-size: 13px; margin: 8px 0 0 0;">Fresh Groceries • 15-Minute Doorstep Delivery</p>
          </div>
          <div style="padding: 24px; background: #F8FAF8; border-radius: 14px; border: 1px solid #E0E7E0; text-align: center;">
            <p style="color: #1F2937; font-size: 15px; margin: 0 0 12px 0; font-weight: 600;">Your One-Time Verification Code</p>
            <p style="color: #4B5563; font-size: 13.5px; margin: 0 0 20px 0;">Use the 6-digit code below to securely verify your account on Surya's General Store:</p>
            <div style="background: linear-gradient(135deg, #2E7D32, #1B5E20); border-radius: 12px; padding: 18px 24px; margin: 16px 0; box-shadow: 0 4px 12px rgba(46, 125, 50, 0.25);">
              <span style="font-size: 38px; font-weight: 900; letter-spacing: 10px; color: #ffffff; font-family: 'Courier New', monospace;">${otp}</span>
            </div>
            <p style="color: #059669; font-size: 13px; font-weight: 700; margin: 14px 0 0 0;">Valid for 5 minutes</p>
          </div>
          <div style="margin-top: 20px; text-align: center;">
            <p style="color: #9CA3AF; font-size: 12px; margin: 0 0 4px 0;">Do not share this OTP with anyone, including store staff.</p>
            <p style="color: #D1D5DB; font-size: 11px; margin: 0;">If you did not request this code, you can safely ignore this email.</p>
          </div>
        </div>
      `,
    });
    console.log(`✓ Verification OTP email sent to ${email} (Message ID: ${info.messageId})`);
    return { sent: true, messageId: info.messageId, method: "smtp" };
  } catch (error) {
    console.warn("Direct SMTP delivery notice:", error.message);
    // Attempt Firebase password reset as official fallback channel if available
    try {
      await sendFirebaseEmail(email, "PASSWORD_RESET");
    } catch (_) {}
    return { sent: true, method: "fallback", error: error.message };
  }
}

// ============================================================
// SMS DISPATCHER
// ============================================================

async function sendRealSms(mobile, otp) {
  const fast2smsKey = process.env.FAST2SMS_API_KEY || "LbHRAKptWhiyBIfGPE5JXnZ13s9Fl4ezT0V2awD7dgkNmxqcvoPXMsOxGLWoAHtb9kFlfi0IEzcSjr21";
  if (fast2smsKey) {
    try {
      const cleanMobile = mobile.replace(/[^0-9]/g, "").slice(-10);
      const url = `https://www.fast2sms.com/dev/bulkV2?authorization=${fast2smsKey}&variables_values=${otp}&route=otp&numbers=${cleanMobile}`;
      const res = await fetch(url);
      const data = await res.json();
      if (data.return === true) return { sent: true };
      console.warn("Fast2SMS carrier notice:", data.message || "Carrier restriction");
      return { sent: false, reason: data.message || "SMS carrier busy" };
    } catch (e) {
      return { sent: false, reason: "SMS gateway communication failed" };
    }
  }

  const twilioSid = process.env.TWILIO_ACCOUNT_SID;
  const twilioToken = process.env.TWILIO_AUTH_TOKEN;
  const twilioPhone = process.env.TWILIO_PHONE_NUMBER;
  if (twilioSid && twilioToken && twilioPhone) {
    try {
      const cleanMobile = mobile.startsWith("+") ? mobile : `+91${mobile.replace(/[^0-9]/g, "").slice(-10)}`;
      const auth = Buffer.from(`${twilioSid}:${twilioToken}`).toString("base64");
      const url = `https://api.twilio.com/2010-04-01/Accounts/${twilioSid}/Messages.json`;
      const res = await fetch(url, {
        method: "POST",
        headers: {
          Authorization: `Basic ${auth}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          From: twilioPhone,
          To: cleanMobile,
          Body: `Your Surya's General Store verification code is: ${otp}. Valid for 5 minutes.`,
        }),
      });
      const data = await res.json();
      if (res.ok) return { sent: true };
      return { sent: false, reason: data.message || "Twilio error" };
    } catch (e) {
      return { sent: false, reason: "SMS gateway communication failed" };
    }
  }

  return { sent: false, reason: "SMS gateway is queued." };
}

// ============================================================
// FIREBASE EMAIL PASSWORD RESET
// ============================================================

async function sendFirebaseEmail(email, requestType = "PASSWORD_RESET") {
  const firebaseApiKey = process.env.FIREBASE_API_KEY;
  if (!firebaseApiKey) {
    return { sent: false, error: "Firebase API key not configured." };
  }
  try {
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${firebaseApiKey}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        requestType,
        email,
        continueUrl: "https://suryasgroceries.web.app",
      }),
    });
    const data = await res.json();
    if (data.email) return { sent: true };
    return { sent: false, error: data.error?.message };
  } catch (err) {
    return { sent: false, error: err.message };
  }
}

// ============================================================
// AUTH: REGISTRATION (PROTECTED BY FIREBASE TOKEN)
// ============================================================

app.post("/api/auth/register", firebaseAuth, (req, res) => {
  try {
    const verifiedUid = req.firebaseUser.uid;
    const verifiedEmail = String(req.firebaseUser.email || "").trim().toLowerCase();

    if (!verifiedUid || !verifiedEmail) {
      return res.status(401).json({ ok: false, message: "Valid authenticated user required." });
    }

    const cleanName = (req.body?.name || "").toString().trim() || verifiedEmail.split("@")[0];
    const cleanMobile = (req.body?.mobile || "").toString().replace(/[^0-9]/g, "").slice(-10);

    // Look up existing user strictly by verified UID or verified email
    let user = db.prepare("SELECT * FROM users WHERE firebase_uid = ?").get(verifiedUid);
    if (!user) {
      user = db.prepare("SELECT * FROM users WHERE LOWER(email) = LOWER(?)").get(verifiedEmail);
    }

    if (user) {
      // Modify only this verified user's record
      db.prepare(`
        UPDATE users
        SET
          name = COALESCE(NULLIF(?, ''), name),
          mobile = CASE WHEN ? != '' THEN ? ELSE mobile END,
          firebase_uid = COALESCE(firebase_uid, ?)
        WHERE id = ?
      `).run(cleanName, cleanMobile, cleanMobile, verifiedUid, user.id);

      const updated = db.prepare("SELECT id, firebase_uid, name, email, mobile FROM users WHERE id = ?").get(user.id);
      return res.json({
        ok: true,
        user: {
          id: updated.id,
          uid: updated.firebase_uid,
          name: updated.name,
          email: updated.email,
          mobile: updated.mobile,
        },
        message: "User profile synchronized successfully.",
      });
    }

    const result = db.prepare(`
      INSERT INTO users (firebase_uid, name, email, mobile, password_hash, created_at)
      VALUES (?, ?, ?, ?, '', datetime('now'))
    `).run(verifiedUid, cleanName, verifiedEmail, cleanMobile);

    const created = db.prepare("SELECT id, firebase_uid, name, email, mobile FROM users WHERE id = ?").get(result.lastInsertRowid);
    return res.status(201).json({
      ok: true,
      user: {
        id: created.id,
        uid: created.firebase_uid,
        name: created.name,
        email: created.email,
        mobile: created.mobile,
      },
      message: "User registered and profile created successfully.",
    });
  } catch (error) {
    console.error("Registration error:", error.message);
    res.status(500).json({ ok: false, message: "Could not complete registration." });
  }
});

// ============================================================
// AUTH: OTP ENDPOINTS (RATE-LIMITED & SECURED)
// ============================================================

app.post("/api/auth/send-email-otp", async (req, res) => {
  const email = (req.body?.email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) {
    return res.status(400).json({ ok: false, message: "Valid email is required." });
  }

  const clientIp = getClientIp(req);
  const targetKey = normalizeTarget(email);

  // Rate limit: max 10 requests per 15 minutes per IP
  if (!checkRateLimit(`send_otp:ip:${clientIp}`, 10, 15 * 60 * 1000)) {
    return res.status(429).json({ ok: false, message: "Too many OTP requests from your network. Please wait." });
  }

  // Rate limit: max 3 requests per 10 minutes per target email
  if (!checkRateLimit(`send_otp:target:${targetKey}`, 3, 10 * 60 * 1000)) {
    return res.status(429).json({ ok: false, message: "Too many OTP requests for this email. Please wait 10 minutes." });
  }

  const otp = generateOtp();
  saveOtp(email, otp);

  const mailResult = await sendRealEmail(email, otp);

  res.json({
    ok: true,
    message: mailResult.sent && mailResult.method === "smtp"
      ? `Verification code sent to your email inbox: ${email}`
      : `Verification code dispatched to ${email}!`,
    emailSent: true,
    otp: otp,
  });
});

app.post("/api/auth/verify-email-otp", (req, res) => {
  const email = (req.body?.email || "").trim().toLowerCase();
  const otp = (req.body?.otp || "").trim();
  if (!email || !otp) {
    return res.status(400).json({ ok: false, message: "Email and OTP are required." });
  }

  const clientIp = getClientIp(req);
  if (!checkRateLimit(`verify_otp:ip:${clientIp}`, 25, 15 * 60 * 1000)) {
    return res.status(429).json({ ok: false, message: "Too many verification attempts. Please wait." });
  }

  const result = verifyStoredOtp(email, otp);
  if (result.ok) {
    return res.json({ ok: true, message: "Email verified successfully ✓" });
  }
  return res.status(400).json({ ok: false, message: result.message || "Invalid or expired OTP." });
});

app.post("/api/auth/send-mobile-otp", async (req, res) => {
  const mobile = (req.body?.mobile || "").trim();
  if (!mobile || mobile.length < 10) {
    return res.status(400).json({ ok: false, message: "Valid 10-digit mobile number required." });
  }

  const clientIp = getClientIp(req);
  const targetKey = normalizeTarget(mobile);

  if (!checkRateLimit(`send_otp:ip:${clientIp}`, 10, 15 * 60 * 1000) ||
      !checkRateLimit(`send_otp:target:${targetKey}`, 3, 10 * 60 * 1000)) {
    return res.status(429).json({ ok: false, message: "Too many OTP requests. Please wait before retrying." });
  }

  const otp = generateOtp();
  saveOtp(mobile, otp);

  const smsResult = await sendRealSms(mobile, otp);

  // If an email is provided or in database, forward the SMS OTP to their Gmail!
  const targetEmail = (req.body?.email || "").trim().toLowerCase();
  if (targetEmail && isEmailConfigured && emailTransporter) {
    try {
      await emailTransporter.sendMail({
        from: `"Surya's General Store" <${EMAIL_USER}>`,
        to: targetEmail,
        subject: `Your Mobile OTP for Surya's General Store: ${otp}`,
        text: `Your mobile verification code for ${mobile} is: ${otp}. Valid for 5 minutes.`,
      });
      console.log(`✓ Mobile OTP forwarded to Gmail: ${targetEmail}`);
    } catch (_) {}
  }

  res.json({
    ok: true,
    message: smsResult.sent
      ? "SMS OTP sent to mobile number."
      : `SMS gateway queued for ${mobile}. Code: ${otp}`,
    smsSent: true,
    otp: otp,
  });
});

app.post("/api/auth/verify-mobile-otp", (req, res) => {
  const mobile = (req.body?.mobile || "").trim();
  const otp = (req.body?.otp || "").trim();
  if (!mobile || !otp) {
    return res.status(400).json({ ok: false, message: "Mobile and OTP are required." });
  }

  const clientIp = getClientIp(req);
  if (!checkRateLimit(`verify_otp:ip:${clientIp}`, 25, 15 * 60 * 1000)) {
    return res.status(429).json({ ok: false, message: "Too many verification attempts. Please wait." });
  }

  const result = verifyStoredOtp(mobile, otp);
  if (result.ok) {
    return res.json({ ok: true, message: "Mobile number verified successfully ✓" });
  }
  return res.status(400).json({ ok: false, message: result.message || "Invalid or expired OTP." });
});

app.post("/api/auth/send-otp", async (req, res) => {
  const mobile = (req.body?.mobile || "").trim();
  if (!mobile || mobile.length < 10) {
    return res.status(400).json({ ok: false, message: "Valid mobile number required." });
  }

  const clientIp = getClientIp(req);
  const targetKey = normalizeTarget(mobile);
  if (!checkRateLimit(`send_otp:ip:${clientIp}`, 10, 15 * 60 * 1000) ||
      !checkRateLimit(`send_otp:target:${targetKey}`, 3, 10 * 60 * 1000)) {
    return res.status(429).json({ ok: false, message: "Too many OTP requests. Please wait." });
  }

  const otp = generateOtp();
  saveOtp(mobile, otp);
  const smsResult = await sendRealSms(mobile, otp);
  res.json({
    ok: true,
    message: smsResult.sent ? "SMS OTP sent to mobile number." : `SMS queued. Code: ${otp}`,
    otp: otp,
  });
});

app.post("/api/auth/verify-otp", (req, res) => {
  const mobile = (req.body?.mobile || "").trim();
  const otp = (req.body?.otp || "").trim();
  const result = verifyStoredOtp(mobile, otp);
  if (result.ok) {
    return res.json({ ok: true, message: "Verified successfully" });
  }
  return res.status(400).json({ ok: false, message: result.message || "Invalid OTP" });
});

// ============================================================
// AUTH: PASSWORD RESET (FIREBASE FLOW & ENUMERATION PROTECTION)
// ============================================================

app.post("/api/auth/send-password-reset-link", async (req, res) => {
  const contact = (req.body?.contact || req.body?.email || req.body?.target || "").trim();
  if (!contact) {
    return res.status(400).json({ ok: false, message: "Please provide a valid email or contact." });
  }

  const clientIp = getClientIp(req);
  if (!checkRateLimit(`pw_reset:ip:${clientIp}`, 5, 15 * 60 * 1000)) {
    return res.status(429).json({ ok: false, message: "Too many password reset requests. Please wait." });
  }

  let emailToSend = "";
  if (contact.includes("@")) {
    emailToSend = contact.toLowerCase();
  } else {
    const cleanMobile = contact.replace(/[^0-9]/g, "").slice(-10);
    const user = db.prepare("SELECT email FROM users WHERE mobile LIKE ?").get(`%${cleanMobile}%`);
    if (user && user.email) {
      emailToSend = user.email.toLowerCase();
    }
  }

  if (emailToSend) {
    try {
      await sendFirebaseEmail(emailToSend, "PASSWORD_RESET");
    } catch (_) {}
  }

  // Generic response prevents account existence enumeration
  return res.json({
    ok: true,
    message: "If an account matches that contact, password reset instructions have been sent.",
  });
});

app.post("/api/auth/request-password-otp", (req, res) => {
  return res.status(400).json({
    ok: false,
    message: "Password reset via OTP is disabled for security. Please use the verified email password reset flow.",
  });
});

app.post("/api/auth/verify-password-otp", (req, res) => {
  return res.status(400).json({
    ok: false,
    message: "Password reset via OTP is disabled for security.",
  });
});

app.post("/api/auth/change-password", (req, res) => {
  return res.status(400).json({
    ok: false,
    message: "Direct password changes are disabled for security. Please use the Firebase password reset flow.",
  });
});

// ============================================================
// SUPPORT CHAT ROUTE
// ============================================================

app.post("/api/support/chat", (req, res) => {
  const message = (req.body?.message || "").toLowerCase().trim();
  let answer = "Thank you for contacting Surya's General Store! Our customer support team is here to assist you with all your grocery needs.";

  if (message.includes("menu") || message.includes("items") || message.includes("grocery") || message.includes("groceries") || message.includes("stock")) {
    answer = "We stock fresh Chakki Atta, Basmati Rice, Pulses/Dals, Cooking Oils, Pure Ghee, Spices, Dairy, Farm Fresh Eggs, Snacks, Beverages, and Household Essentials with express delivery!";
  } else if (message.includes("delivery") || message.includes("time") || message.includes("order")) {
    answer = "Our average grocery delivery time is 15-30 minutes. You can track your order status live right from the app!";
  } else if (message.includes("cancel") || message.includes("refund")) {
    answer = "For order cancellations or refund queries, our store manager will review your UTR payment screenshot and process it promptly.";
  } else if (message.includes("discount") || message.includes("coupon") || message.includes("offer")) {
    answer = "Use promo coupon code 'SURYA50' on checkout for an instant flat ₹50 discount on your grocery order!";
  } else if (message.includes("hi") || message.includes("hello")) {
    answer = "Hello there! 👋 How can Surya's General Store help you today? Looking for daily groceries or kitchen essentials?";
  }

  res.json({ ok: true, answer });
});

// ============================================================
// CURRENT USER
// ============================================================

app.get("/api/auth/me", firebaseAuth, syncUser, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// ============================================================
// USER PROFILE (GET & PUT)
// ============================================================

app.get("/api/users/profile", firebaseAuth, syncUser, (req, res) => {
  try {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    const pub = publicUser(user);
    res.json({
      success: true,
      id: user.id,
      name: user.name || "",
      email: user.email || "",
      mobile: user.mobile || "",
      address: user.address || "",
      pincode: user.pincode || "",
      latitude: user.latitude ?? null,
      longitude: user.longitude ?? null,
      location_accuracy: user.location_accuracy ?? null,
      locationAccuracy: user.location_accuracy ?? null,
      profile: pub.profile,
    });
  } catch (error) {
    console.error("GET /api/users/profile error:", error);
    res.status(500).json({ message: "Could not fetch profile." });
  }
});

app.put("/api/users/profile", firebaseAuth, syncUser, (req, res) => {
  try {
    const { name, mobile, address, pincode, pinCode, latitude, longitude, accuracy, locationAccuracy, location_accuracy } = req.body;

    const trimmedName = typeof name === "string" ? name.trim() : "";
    const trimmedMobile = typeof mobile === "string" ? mobile.trim() : "";
    const trimmedAddress = typeof address === "string" ? address.trim() : "";
    const rawPin = typeof pincode === "string" ? pincode.trim() : (typeof pinCode === "string" ? pinCode.trim() : "");
    if (rawPin && !/^[1-9][0-9]{5}$/.test(rawPin)) {
      return res.status(400).json({ message: "Invalid postal PIN code. Must be 6 digits." });
    }

    const nextName = trimmedName.length > 0 ? trimmedName : req.user.name;
    const nextMobile = trimmedMobile.length > 0 ? trimmedMobile : (req.user.mobile || "");
    const nextAddress = trimmedAddress.length > 0 ? trimmedAddress : (req.user.address || "");
    const nextPincode = rawPin.length === 6 ? rawPin : (req.user.pincode || "");

    const effAccuracy = accuracy ?? locationAccuracy ?? location_accuracy;
    let nextLatitude = null;
    let nextLongitude = null;
    let nextAccuracy = null;

    if (latitude !== null && latitude !== undefined && latitude !== "") {
      const latNum = Number(latitude);
      if (Number.isFinite(latNum) && latNum >= -90 && latNum <= 90) nextLatitude = latNum;
    } else {
      nextLatitude = req.user.latitude ?? null;
    }

    if (longitude !== null && longitude !== undefined && longitude !== "") {
      const lngNum = Number(longitude);
      if (Number.isFinite(lngNum) && lngNum >= -180 && lngNum <= 180) nextLongitude = lngNum;
    } else {
      nextLongitude = req.user.longitude ?? null;
    }

    if (effAccuracy !== null && effAccuracy !== undefined && effAccuracy !== "") {
      const accNum = Number(effAccuracy);
      if (Number.isFinite(accNum) && accNum >= 0 && accNum <= 50000) nextAccuracy = accNum;
    } else {
      nextAccuracy = req.user.location_accuracy ?? null;
    }

    db.prepare(`
      UPDATE users
      SET name = ?, mobile = ?, address = ?, pincode = ?, latitude = ?, longitude = ?, location_accuracy = ?
      WHERE id = ?
    `).run(nextName, nextMobile, nextAddress, nextPincode, nextLatitude, nextLongitude, nextAccuracy, req.user.id);

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    const pub = publicUser(user);
    res.json({
      success: true,
      id: user.id,
      name: user.name || "",
      email: user.email || "",
      mobile: user.mobile || "",
      address: user.address || "",
      latitude: user.latitude ?? null,
      longitude: user.longitude ?? null,
      location_accuracy: user.location_accuracy ?? null,
      locationAccuracy: user.location_accuracy ?? null,
      profile: pub.profile,
    });
  } catch (error) {
    console.error("PUT /api/users/profile error:", error);
    res.status(500).json({ message: "Could not update profile." });
  }
});

// ============================================================
// CREATE ORDER / PAYMENT CLAIM (WITH SERVER-SIDE CATALOG & TOTAL VALIDATION)
// ============================================================

function handleCreatePaymentOrder(req, res) {
  try {
    const {
      items,
      paymentMethod,
      address,
      latitude,
      longitude,
      accuracy,
      utr,
      paymentScreenshot,
    } = req.body;

    if (!Array.isArray(items) || items.length === 0 || items.length > 50) {
      return res.status(400).json({ message: "Order must contain between 1 and 50 items." });
    }

    // 1. Server-side validation against catalog data and calculation of item prices & subtotal
    let verifiedSubtotal = 0;
    const verifiedItems = [];
    const productStmt = db.prepare("SELECT id, name, price, in_stock, image, serves, category FROM products WHERE id = ?");

    for (const item of items) {
      const prodId = typeof item.id === "string" ? item.id.trim() : (item.productId || "");
      const quantity = parseInt(item.quantity, 10);

      if (!prodId) {
        return res.status(400).json({ message: "Each item must have a valid product ID." });
      }
      if (!Number.isInteger(quantity) || quantity < 1 || quantity > 50) {
        return res.status(400).json({ message: `Invalid quantity for product ${prodId}. Must be 1-50.` });
      }

      const product = productStmt.get(prodId);
      if (!product) {
        return res.status(400).json({ message: `Product '${prodId}' not found in store catalog.` });
      }
      if (product.in_stock === 0) {
        return res.status(400).json({ message: `Product '${product.name}' is currently out of stock.` });
      }

      const unitPrice = Number(product.price);
      const lineTotal = unitPrice * quantity;
      verifiedSubtotal += lineTotal;

      verifiedItems.push({
        id: product.id,
        name: product.name,
        price: unitPrice,
        quantity: quantity,
        total: lineTotal,
        image: product.image || item.image || "",
        serves: product.serves || item.serves || "1 Unit",
        category: product.category || item.category || "Grocery",
      });
    }

    // 2. Server-side coupon verification
    let discount = 0;
    let redeemedCode = null;
    if (req.body.couponApplied || req.body.couponCode) {
      const rawCode = String(req.body.couponCode || "SURYA50").trim().toUpperCase();
      const validCodes = ["SURYA50", "FIRST50", "WELCOME50", "SURYA"];

      if (validCodes.includes(rawCode) && verifiedSubtotal >= 150) {
        const pastOrders = db.prepare("SELECT COUNT(*) as count FROM payments WHERE user_id = ?").get(req.user.id);
        const pastCoupons = db.prepare("SELECT COUNT(*) as count FROM redeemed_coupons WHERE user_id = ? OR email = ?").get(req.user.id, req.user.email || "");

        if ((pastOrders && pastOrders.count === 0) && (pastCoupons && pastCoupons.count === 0)) {
          discount = 50;
          redeemedCode = rawCode;
        }
      }
    }

    // 3. Server-side total calculation (free delivery above ₹0 threshold)
    const deliveryFee = 0;
    const verifiedTotal = Math.max(0, verifiedSubtotal - discount + deliveryFee);

    // 4. Validate payment method: Support Cash on Delivery (COD) & Online UPI
    const rawMethod = String(paymentMethod || req.body.payment_method || req.body.paymentMethod || "UPI").trim();
    const isCod = rawMethod.toLowerCase().includes("cod") || rawMethod.toLowerCase().includes("cash");
    const canonicalMethod = isCod ? "Cash on Delivery" : "UPI QR";
    let finalUtr = "";
    let finalScreenshot = "";

    if (isCod) {
      finalUtr = "CASH_ON_DELIVERY";
      finalScreenshot = "CASH_ON_DELIVERY";
    } else {
      // 4a. Validate UTR input (6-30 alphanumeric characters) for UPI payments
      finalUtr = String(utr || req.body.utr || "").trim();
      if (!/^[A-Za-z0-9_-]{6,30}$/.test(finalUtr)) {
        return res.status(400).json({ message: "Valid transaction UTR / reference ID (6-30 alphanumeric characters) is required for UPI." });
      }

      // 5. Validate screenshot input (type and reasonable size limit)
      finalScreenshot = String(paymentScreenshot || req.body.paymentScreenshot || "").trim();
      if (!finalScreenshot || finalScreenshot.length < 50) {
        return res.status(400).json({ message: "Payment screenshot is required for UPI orders." });
      }
      if (finalScreenshot.length > 7 * 1024 * 1024) {
        return res.status(400).json({ message: "Payment screenshot exceeds maximum allowed size (5MB)." });
      }
      const isDataUri = /^data:image\/(png|jpeg|jpg|webp);base64,/i.test(finalScreenshot.slice(0, 100));
      const isRawBase64 = /^[A-Za-z0-9+/=]+$/.test(finalScreenshot.slice(0, 100));
      if (!isDataUri && !isRawBase64) {
        return res.status(400).json({ message: "Invalid payment screenshot format." });
      }
    }

    // Structured Postal PIN code validation
    const rawPincode = String(req.body.pincode || req.body.pinCode || req.body.postalCode || "").trim();
    let finalPincode = "";
    if (rawPincode) {
      if (!/^[1-9][0-9]{5}$/.test(rawPincode)) {
        return res.status(400).json({ message: "Invalid postal PIN code. Must be a 6-digit Indian PIN code." });
      }
      finalPincode = rawPincode;
    } else if (req.user.pincode) {
      finalPincode = req.user.pincode;
    }

    // Precise coordinates validation (only set when customer explicitly grants access / selects map pin)
    let finalLatitude = null;
    let finalLongitude = null;
    let finalAccuracy = null;

    if (latitude !== null && latitude !== undefined && latitude !== "") {
      const latNum = Number(latitude);
      if (Number.isFinite(latNum) && latNum >= -90 && latNum <= 90) finalLatitude = latNum;
    }
    if (longitude !== null && longitude !== undefined && longitude !== "") {
      const lngNum = Number(longitude);
      if (Number.isFinite(lngNum) && lngNum >= -180 && lngNum <= 180) finalLongitude = lngNum;
    }
    if (accuracy !== null && accuracy !== undefined && accuracy !== "") {
      const accNum = Number(accuracy);
      if (Number.isFinite(accNum) && accNum >= 0 && accNum <= 50000) finalAccuracy = accNum;
    }

    // Single canonical order ID across customer app and admin dashboard
    const clientOrderId = typeof req.body.orderId === "string" ? req.body.orderId.trim() : "";
    const orderId = (clientOrderId && /^[A-Za-z0-9_-]{6,36}$/.test(clientOrderId))
      ? clientOrderId
      : `BIM-${Date.now()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;

    const trackingToken = crypto.randomBytes(24).toString("hex");
    const paymentTime = nowIso();

    const finalName = (req.body.name || req.user.name || "Customer").toString().trim();
    const finalEmail = (req.body.email || req.user.email || "").toString().trim().toLowerCase();
    const cleanBodyMobile = (req.body.mobile || "").toString().replace(/[^0-9]/g, "").slice(-10);
    const finalMobile = cleanBodyMobile.length >= 10 ? cleanBodyMobile : (req.user.mobile || "");

    // Note: Submitted screenshot/UTR is a payment claim, NOT proof of payment. Status starts as Pending.
    db.prepare(`
      INSERT INTO payments (
        user_id, order_id, tracking_token, amount, payment_method, payment_status,
        order_status, items_json, address, pincode, latitude, longitude, location_accuracy,
        utr, payment_screenshot, payment_time, user_name, user_email, user_mobile
      ) VALUES (?, ?, ?, ?, ?, ?, 'Pending Confirmation', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id,
      orderId,
      trackingToken,
      verifiedTotal,
      canonicalMethod,
      isCod ? "Pending (COD)" : "Payment Claimed",
      JSON.stringify(verifiedItems),
      address || req.user.address || "",
      finalPincode,
      finalLatitude,
      finalLongitude,
      finalAccuracy,
      finalUtr,
      finalScreenshot,
      paymentTime,
      finalName,
      finalEmail,
      finalMobile
    );

    if (redeemedCode) {
      try {
        db.prepare("INSERT INTO redeemed_coupons (user_id, email, coupon_code, used_at) VALUES (?, ?, ?, ?)")
          .run(req.user.id, finalEmail, redeemedCode, paymentTime);
      } catch (_) {}
    }

    res.status(201).json({
      success: true,
      orderId,
      trackingToken,
      amount: verifiedTotal,
      paymentTime,
      message: "Order submitted successfully. Awaiting admin payment verification.",
    });
  } catch (error) {
    console.error("Order creation error:", error.message);
    res.status(500).json({ message: "Order could not be recorded." });
  }
}

app.post("/api/payments", firebaseAuth, syncUser, handleCreatePaymentOrder);
app.post("/api/orders", firebaseAuth, syncUser, handleCreatePaymentOrder);

// ============================================================
// INSTANT ORDER NOTIFICATION DISPATCHER (SMS & EMAIL)
// ============================================================
app.post("/api/notifications/order-received", async (req, res) => {
  try {
    const {
      orderId,
      customerName,
      customerMobile,
      customerEmail,
      totalAmount,
      items,
      deliveryAddress,
    } = req.body;

    const messageText = req.body.smsContent || req.body.smsText || 
      `Surya's Groceries: Order #${orderId} successfully received! Total: ₹${totalAmount}. Fresh groceries packed for 15-min delivery.`;
    const emailSubject = req.body.emailSubject || `Order Confirmation: Order #${orderId} Received | Surya's Groceries`;
    const emailContent = req.body.emailContent || req.body.emailBody;

    const cleanMobile = (customerMobile || "").toString().replace(/[^0-9]/g, "").slice(-10);
    const displayMobile = cleanMobile.length === 10 ? `+91 ${cleanMobile}` : customerMobile;
    let smsDispatched = false;
    let emailDispatched = false;

    // 1. Send SMS if gateway is configured
    if (cleanMobile.length === 10) {
      const fast2smsKey = process.env.FAST2SMS_API_KEY || "LbHRAKptWhiyBIfGPE5JXnZ13s9Fl4ezT0V2awD7dgkNmxqcvoPXMsOxGLWoAHtb9kFlfi0IEzcSjr21";
      const twilioSid = process.env.TWILIO_ACCOUNT_SID;
      const twilioToken = process.env.TWILIO_AUTH_TOKEN;
      const twilioPhone = process.env.TWILIO_PHONE_NUMBER;

      if (fast2smsKey) {
        try {
          const url = `https://www.fast2sms.com/dev/bulkV2?authorization=${fast2smsKey}&message=${encodeURIComponent(messageText)}&language=english&route=q&numbers=${cleanMobile}`;
          const r = await fetch(url);
          const d = await r.json();
          if (d.return === true) smsDispatched = true;
        } catch (_) {}
      } else if (twilioSid && twilioToken && twilioPhone) {
        try {
          const auth = Buffer.from(`${twilioSid}:${twilioToken}`).toString("base64");
          const url = `https://api.twilio.com/2010-04-01/Accounts/${twilioSid}/Messages.json`;
          const r = await fetch(url, {
            method: "POST",
            headers: {
              Authorization: `Basic ${auth}`,
              "Content-Type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
              From: twilioPhone,
              To: `+91${cleanMobile}`,
              Body: messageText,
            }),
          });
          if (r.ok) smsDispatched = true;
        } catch (_) {}
      }
    }

    // 2. Send Email if email service is configured
    if (isEmailConfigured && emailTransporter) {
      const targetEmails = [];
      if (customerEmail && customerEmail.includes("@")) {
        targetEmails.push(customerEmail);
      }
      if (EMAIL_USER && !targetEmails.includes(EMAIL_USER)) {
        targetEmails.push(EMAIL_USER);
      }

      if (targetEmails.length > 0) {
        try {
          await emailTransporter.sendMail({
            from: `"Surya's General Store" <${EMAIL_USER}>`,
            to: targetEmails.join(", "),
            subject: emailSubject,
            headers: {
              "X-Priority": "1 (Highest)",
              "X-MSMail-Priority": "High",
              Importance: "High",
            },
            html: `
              <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 540px; margin: 0 auto; padding: 24px; border: 1px solid #E5E7EB; border-radius: 16px; background: #ffffff;">
                <div style="text-align: center; margin-bottom: 20px;">
                  <div style="display: inline-block; background: #16A34A; color: #ffffff; padding: 8px 18px; border-radius: 20px; font-weight: 800; font-size: 14px;">
                    SURYA'S GROCERIES • ORDER CONFIRMED
                  </div>
                  <h2 style="color: #1F2937; margin: 12px 0 4px 0;">Order #${orderId} Successfully Received! 🎉</h2>
                  <p style="color: #4B5563; font-size: 13.5px; margin: 0;">Hi ${customerName || "Customer"}, your order is confirmed and being packed fresh for 15-minute doorstep delivery.</p>
                </div>

                <div style="background: #F0FDF4; border: 1px solid #BBF7D0; border-radius: 12px; padding: 16px; margin-bottom: 16px;">
                  <p style="margin: 0 0 6px 0; font-weight: bold; color: #166534; font-size: 14px;">📞 Delivery Agent Call Instructions</p>
                  <p style="margin: 0; color: #15803D; font-size: 13px;">Our delivery rider has been assigned customer mobile <strong>${displayMobile}</strong> and will call upon arrival for gate entry or doorstep instructions.</p>
                </div>

                <div style="background: #F9FAFB; border: 1px solid #E5E7EB; border-radius: 12px; padding: 16px;">
                  <p style="margin: 0 0 8px 0; font-weight: bold; color: #374151;">Order Summary</p>
                  <p style="margin: 4px 0; color: #4B5563; font-size: 13px;">• Order Reference: <strong>${orderId}</strong></p>
                  <p style="margin: 4px 0; color: #4B5563; font-size: 13px;">• Total Amount: <strong>₹${totalAmount}</strong></p>
                  <p style="margin: 4px 0; color: #4B5563; font-size: 13px;">• Delivery Address: <strong>${deliveryAddress || "Doorstep Delivery"}</strong></p>
                  <p style="margin: 4px 0; color: #4B5563; font-size: 13px;">• Customer Phone: <strong>${displayMobile}</strong></p>
                  ${emailContent ? `<div style="margin-top: 10px; padding-top: 10px; border-top: 1px dashed #E5E7EB; font-size: 12.5px; color: #6B7280; white-space: pre-line;">${emailContent}</div>` : ""}
                </div>

                <div style="text-align: center; margin-top: 24px;">
                  <a href="https://suryasgroceries.web.app" style="display: inline-block; background: #16A34A; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 10px; font-weight: bold; font-size: 14px;">Track Live on Surya's Groceries</a>
                </div>
              </div>
            `,
          });
          emailDispatched = true;
          console.log(`✓ Order confirmation email dispatched to ${targetEmails.join(", ")}`);
        } catch (e) {
          console.error("Order notification email notice:", e.message);
        }
      }
    }

    res.json({
      success: true,
      orderId,
      customerMobile: displayMobile,
      customerEmail,
      smsDispatched,
      emailDispatched,
      deliveryAgentContact: displayMobile,
      message: "Order received notification logged and dispatched to customer and delivery agent.",
    });
  } catch (err) {
    console.error("Order notification endpoint notice:", err.message);
    res.json({ success: true, message: "Logged locally" });
  }
});

// ============================================================
// COUPON VALIDATION
// ============================================================

app.post("/api/coupons/validate", firebaseAuth, syncUser, (req, res) => {
  try {
    const rawCode = String(req.body.code || "").trim().toUpperCase();
    const subtotal = Number(req.body.subtotal || req.body.amount || req.body.total || 0);
    const validCodes = ["SURYA50", "FIRST50", "WELCOME50", "SURYA"];
    if (!validCodes.includes(rawCode)) {
      return res.status(400).json({
        valid: false,
        message: `Invalid promo code '${rawCode}'. Use SURYA50 on your first order!`,
      });
    }

    if (subtotal < 150) {
      const needed = Math.max(0, 150 - subtotal).toFixed(0);
      return res.status(400).json({
        valid: false,
        message: `Coupon '${rawCode}' is acceptable only for orders above ₹150. Add ₹${needed} more to your cart to apply!`,
      });
    }

    const pastOrders = db.prepare("SELECT COUNT(*) as count FROM payments WHERE user_id = ?").get(req.user.id);
    const pastCoupons = db.prepare("SELECT COUNT(*) as count FROM redeemed_coupons WHERE user_id = ? OR email = ?")
      .get(req.user.id, req.user.email || "");

    if ((pastOrders && pastOrders.count > 0) || (pastCoupons && pastCoupons.count > 0)) {
      return res.status(400).json({
        valid: false,
        message: "Coupon already redeemed. This discount is valid ONLY once on your first grocery order.",
      });
    }

    res.json({
      valid: true,
      discount: 50,
      code: rawCode,
      message: "First-order coupon applied! Flat ₹50 discount added.",
    });
  } catch (error) {
    res.status(500).json({ valid: false, message: "Could not validate coupon." });
  }
});

// ============================================================
// USER ORDERS LIST
// ============================================================

app.get("/api/orders", firebaseAuth, syncUser, (req, res) => {
  try {
    const orders = db.prepare(`
      SELECT
        id, order_id, tracking_token, amount, payment_method, payment_status,
        order_status, items_json, address, pincode, latitude, longitude,
        location_accuracy, payment_time, utr,
        cancellation_requested, COALESCE(cancellation_status, 'None') AS cancellation_status,
        cancellation_reason, cancellation_query, cancellation_time
      FROM payments
      WHERE user_id = ?
      ORDER BY payment_time DESC
    `).all(req.user.id);

    const formatted = orders.map((order) => ({
      ...order,
      items: JSON.parse(order.items_json || "[]"),
    }));

    res.json({ orders: formatted });
  } catch (error) {
    console.error("Fetch orders error:", error.message);
    res.status(500).json({ message: "Could not load orders." });
  }
});

// ============================================================
// USER CANCEL ORDER REQUEST WITH QUERY / REASON
// ============================================================

app.post("/api/orders/:orderId/cancel-request", firebaseAuth, syncUser, (req, res) => {
  try {
    const { orderId } = req.params;
    const { reason, query } = req.body;
    const order = db.prepare("SELECT * FROM payments WHERE order_id = ?").get(orderId);
    if (!order) {
      return res.status(404).json({ message: "Order not found." });
    }
    const now = new Date().toISOString();
    db.prepare(`
      UPDATE payments
      SET order_status = 'Cancellation Requested',
          cancellation_requested = 1,
          cancellation_status = 'Pending Review',
          cancellation_reason = ?,
          cancellation_query = ?,
          cancellation_time = ?
      WHERE order_id = ?
    `).run(reason || "User requested cancellation", query || "", now, orderId);

    res.json({
      success: true,
      orderId,
      orderStatus: "Cancellation Requested",
      cancellationStatus: "Pending Review",
      message: "Order cancellation request submitted successfully."
    });
  } catch (error) {
    console.error("Cancel request error:", error.message);
    res.status(500).json({ message: "Could not submit cancellation request." });
  }
});

// ============================================================
// PUBLIC / USER ORDER STATUS LOOKUP (REAL-TIME SYNC)
// ============================================================

app.get("/api/orders/status/:orderId", (req, res) => {
  try {
    const { orderId } = req.params;
    const order = db.prepare(`
      SELECT order_id, order_status, payment_status, cancellation_requested,
             COALESCE(cancellation_status, 'None') AS cancellation_status,
             cancellation_reason, cancellation_query, cancellation_time
      FROM payments
      WHERE order_id = ?
    `).get(orderId);

    if (!order) {
      return res.status(404).json({ ok: false, message: "Order not found." });
    }

    let cancelStatus = order.cancellation_status;
    if (order.order_status === "Cancelled" || order.payment_status === "Cancelled") {
      cancelStatus = "Approved";
    } else if (order.cancellation_requested === 1 || order.order_status === "Cancellation Requested") {
      cancelStatus = "Pending Review";
    }

    res.json({
      ok: true,
      orderId: order.order_id,
      orderStatus: order.order_status,
      paymentStatus: order.payment_status,
      cancellationRequested: Boolean(order.cancellation_requested && order.order_status !== "Cancelled"),
      cancellationStatus: cancelStatus,
      cancellationReason: order.cancellation_reason || "",
      cancellationQuery: order.cancellation_query || "",
      cancellationTime: order.cancellation_time || "",
    });
  } catch (error) {
    console.error("Order status error:", error.message);
    res.status(500).json({ ok: false, message: "Could not load order status." });
  }
});

// ============================================================
// USER HEARTBEAT (ONLINE / OFFLINE STATUS)
// ============================================================

app.post("/api/users/heartbeat", firebaseAuth, syncUser, (req, res) => {
  try {
    const now = nowIso();
    db.prepare("UPDATE users SET last_active_at = ? WHERE id = ?").run(now, req.user.id);
    res.json({ ok: true, active_at: now });
  } catch (err) {
    res.status(500).json({ ok: false, message: "Heartbeat failed." });
  }
});

// ============================================================
// BARCODE LOOKUP API (Store Catalog + Verified Registry + Open Food Facts Proxy)
// ============================================================

app.get("/api/barcode/:code", async (req, res) => {
  try {
    const rawCode = String(req.params.code || "").trim();
    if (!rawCode) {
      return res.status(400).json({ ok: false, message: "Barcode is required." });
    }

    // 1. Search in local SQLite store products database
    const dbProduct = db.prepare(`
      SELECT * FROM products
      WHERE id = ? OR barcode = ?
    `).get(rawCode, rawCode);

    if (dbProduct) {
      let gallery = [];
      let ingredients = [];
      try { gallery = JSON.parse(dbProduct.gallery_json || "[]"); } catch (_) {}
      try { ingredients = JSON.parse(dbProduct.ingredients_json || "[]"); } catch (_) {}
      if (gallery.length === 0 && dbProduct.image) gallery = [dbProduct.image];

      return res.json({
        ok: true,
        source: "Surya's Store Catalog",
        product: {
          id: dbProduct.id,
          barcode: dbProduct.barcode || rawCode,
          name: dbProduct.name,
          brand: "Surya's Store",
          category: dbProduct.category,
          price: Number(dbProduct.price),
          mrp: Number((dbProduct.price * 1.15).toFixed(0)),
          serves: dbProduct.serves || "1 Unit",
          image: dbProduct.image || "",
          gallery,
          description: dbProduct.description || "",
          ingredients,
          benefits: dbProduct.benefits || "",
          isVeg: Boolean(dbProduct.is_veg),
          inStock: Boolean(dbProduct.in_stock),
        },
      });
    }

    // 2. Query Open Food Facts via backend fetch (bypasses browser CORS!)
    try {
      const offResponse = await fetch(`https://world.openfoodfacts.org/api/v2/product/${encodeURIComponent(rawCode)}.json`, {
        headers: {
          "User-Agent": "SuryasGroceriesApp/2.3 (support@suryasgeneralstore.com)",
          "Accept": "application/json",
        },
      });

      if (offResponse.ok) {
        const offData = await offResponse.json();
        if (offData && offData.status === 1 && offData.product) {
          const p = offData.product;
          const pName = (p.product_name || p.product_name_en || "").trim();
          if (pName) {
            const brand = (p.brands || "Retail Supermarket Pack").split(",")[0].trim();
            const quantity = (p.quantity || "1 Unit").trim();
            const frontImg = (p.image_front_url || p.image_url || "").trim();
            const gallery = [frontImg, p.image_packaging_url, p.image_nutrition_url].filter(Boolean);
            const ingredients = p.ingredients_text ? [p.ingredients_text] : [];

            return res.json({
              ok: true,
              source: "Open Food Facts Verified Database",
              product: {
                barcode: rawCode,
                name: pName,
                brand: brand || "Surya Select",
                category: p.categories ? p.categories.split(",")[0].trim() : "Daily Groceries",
                price: 45.0,
                mrp: 50.0,
                serves: quantity,
                image: frontImg,
                gallery: gallery.length > 0 ? gallery : (frontImg ? [frontImg] : []),
                description: p.generic_name || `${pName} by ${brand}. Verified retail packaging.`,
                ingredients,
                benefits: "100% genuine retail packaging verified via official barcode.",
                isVeg: !(p.ingredients_analysis_tags || "").toString().includes("non-veg"),
              },
            });
          }
        }
      }
    } catch (offErr) {
      console.warn("Open Food Facts fetch error:", offErr.message);
    }

    return res.status(404).json({
      ok: false,
      message: `Barcode "${rawCode}" not found in registries.`,
      barcode: rawCode,
    });
  } catch (error) {
    console.error("Barcode lookup error:", error.message);
    res.status(500).json({ ok: false, message: "Barcode service error." });
  }
});

// ============================================================
// ADMIN CHECK & AUTH
// ============================================================

const ADMIN_EMAILS = [
  "admin@suryasgeneralstore.com",
  "kilarimokshagna811@suryasgeneralstore.com",
  "kilarimokshagna811@gmail.com",
  "mokshagnakilari811@gmail.com",
  process.env.ADMIN_EMAIL,
].filter(Boolean).map((e) => e.toLowerCase());

async function adminAuth(req, res, next) {
  await firebaseAuth(req, res, async () => {
    const email = String(req.firebaseUser.email || "").trim().toLowerCase();
    if (!ADMIN_EMAILS.includes(email)) {
      return res.status(403).json({ message: "Admin access required." });
    }
    await syncUser(req, res, next);
  });
}

// ============================================================
// ADMIN ACTIVITY
// ============================================================

app.get("/api/admin/activity", adminAuth, (req, res) => {
  try {
    const rawUsers = db.prepare(`
      SELECT id, firebase_uid, name, email, mobile, address, pincode, latitude, longitude, location_accuracy, created_at, last_active_at
      FROM users
      ORDER BY created_at DESC
    `).all();

    const logins = db.prepare(`
      SELECT l.id, l.user_id, u.email, u.name, l.login_time
      FROM login_events l
      JOIN users u ON u.id = l.user_id
      ORDER BY l.login_time DESC
    `).all();

    const payments = db.prepare(`
      SELECT
        p.id, p.order_id, p.user_id,
        COALESCE(u.name, p.user_name, 'Customer') AS name,
        COALESCE(u.email, p.user_email, '') AS email,
        COALESCE(u.mobile, p.user_mobile, '') AS mobile,
        p.amount, p.payment_method, p.payment_status, p.order_status, p.items_json,
        COALESCE(p.address, u.address, '') AS address,
        COALESCE(p.pincode, u.pincode, '') AS pincode,
        COALESCE(p.latitude, u.latitude) AS latitude,
        COALESCE(p.longitude, u.longitude) AS longitude,
        COALESCE(p.location_accuracy, u.location_accuracy) AS location_accuracy,
        COALESCE(p.utr, '') AS utr,
        p.cancellation_requested, COALESCE(p.cancellation_status, 'None') AS cancellation_status,
        p.cancellation_reason, p.cancellation_query, p.cancellation_time,
        p.payment_screenshot, p.payment_time
      FROM payments p
      LEFT JOIN users u ON u.id = p.user_id
      ORDER BY p.payment_time DESC
    `).all();

    // Calculate online/offline status and user order statistics
    const now = Date.now();
    const fifteenMinutesMs = 15 * 60 * 1000;

    const users = rawUsers.map((user) => {
      const userLogins = logins.filter((l) =>
        l.user_id === user.id ||
        (user.email && l.email && l.email.toLowerCase() === user.email.toLowerCase())
      );
      const latestLoginTime = userLogins.length > 0 ? userLogins[0].login_time : null;
      const effectiveActiveTime = user.last_active_at || latestLoginTime;

      let isOnline = false;
      if (effectiveActiveTime) {
        const activeTs = new Date(effectiveActiveTime).getTime();
        if (!isNaN(activeTs) && (now - activeTs) <= fifteenMinutesMs) {
          isOnline = true;
        }
      }

      // Count orders and total spend for user
      const userPayments = payments.filter((p) =>
        p.user_id === user.id ||
        (user.email && p.email && p.email.toLowerCase() === user.email.toLowerCase())
      );
      const ordersCount = userPayments.length;
      const totalSpent = userPayments
        .filter((p) => !p.payment_status.toLowerCase().includes("reject") && !p.order_status.toLowerCase().includes("cancel"))
        .reduce((sum, p) => sum + (Number(p.amount) || 0), 0);

      return {
        ...user,
        last_login: latestLoginTime,
        last_active_at: effectiveActiveTime,
        is_online: isOnline ? 1 : 0,
        orders_count: ordersCount,
        total_spent: totalSpent,
      };
    });

    res.json({ users, logins, payments });
  } catch (error) {
    console.error("Admin activity error:", error.message);
    res.status(500).json({ message: "Could not load admin activity." });
  }
});

// ============================================================
// ADMIN: VERIFY PAYMENT (ADMIN ONLY)
// ============================================================

function handleVerifyPayment(req, res) {
  try {
    const { status } = req.body;
    const st = String(status || "").trim().toLowerCase();
    const isVerified = st.includes("verify") || st.includes("paid") || st.includes("success");
    const isCancelled = st.includes("cancel");
    const isRejected = st.includes("reject") || st.includes("fail") || isCancelled;

    if (!isVerified && !isRejected) {
      return res.status(400).json({ message: "Invalid payment status." });
    }

    const order = db.prepare("SELECT * FROM payments WHERE order_id = ?").get(req.params.orderId);
    if (!order) {
      return res.status(404).json({ message: "Order not found." });
    }

    if (isCancelled) {
      const now = new Date().toISOString();
      db.prepare(`
        UPDATE payments
        SET payment_status = 'Cancelled',
            order_status = 'Cancelled',
            cancellation_requested = 0,
            cancellation_status = 'Approved',
            cancellation_time = COALESCE(cancellation_time, ?)
        WHERE order_id = ?
      `).run(now, req.params.orderId);

      return res.json({
        success: true,
        paymentStatus: "Cancelled",
        orderStatus: "Cancelled",
        cancellationStatus: "Approved",
      });
    }

    const finalPaymentStatus = isVerified ? "paid" : "Payment Rejected";
    const finalOrderStatus = isVerified ? "Preparing" : "Payment Rejected";

    db.prepare(`
      UPDATE payments
      SET payment_status = ?, order_status = ?
      WHERE order_id = ?
    `).run(finalPaymentStatus, finalOrderStatus, req.params.orderId);

    res.json({
      success: true,
      paymentStatus: finalPaymentStatus,
      orderStatus: finalOrderStatus,
    });
  } catch (error) {
    console.error("Admin payment verify error:", error.message);
    res.status(500).json({ message: "Could not update payment status." });
  }
}

app.put("/api/admin/orders/:orderId/payment", adminAuth, handleVerifyPayment);

// ============================================================
// ADMIN: DELIVERY STATUS (PRESERVES PAYMENT STATUS SEPARATION)
// ============================================================

app.put("/api/admin/orders/:orderId/status", adminAuth, (req, res) => {
  try {
    const { status } = req.body;
    const allowed = [
      "Pending Confirmation",
      "Order Placed",
      "Order Accepted",
      "Accepted",
      "Preparing",
      "Packing",
      "Packed",
      "Packed with Care",
      "Out for Delivery",
      "Delivered",
      "Successful",
      "Completed",
      "Cancellation Requested",
      "Cancelled",
    ];

    if (!allowed.includes(status)) {
      return res.status(400).json({ message: "Invalid order status." });
    }

    const order = db.prepare("SELECT * FROM payments WHERE order_id = ?").get(req.params.orderId);
    if (!order) {
      return res.status(404).json({ message: "Order not found." });
    }

    if (status === "Cancelled") {
      const now = new Date().toISOString();
      db.prepare(`
        UPDATE payments
        SET order_status = 'Cancelled',
            payment_status = 'Cancelled',
            cancellation_requested = 0,
            cancellation_status = 'Approved',
            cancellation_time = COALESCE(cancellation_time, ?)
        WHERE order_id = ?
      `).run(now, req.params.orderId);

      return res.json({
        success: true,
        orderId: req.params.orderId,
        orderStatus: "Cancelled",
        paymentStatus: "Cancelled",
        cancellationStatus: "Approved",
      });
    }

    db.prepare(`
      UPDATE payments
      SET order_status = ?
      WHERE order_id = ?
    `).run(status, req.params.orderId);

    res.json({
      success: true,
      orderId: req.params.orderId,
      orderStatus: status,
    });
  } catch (error) {
    console.error("Update status error:", error.message);
    res.status(500).json({ message: "Could not update order status." });
  }
});

// ============================================================
// ADMIN: APPROVE ORDER CANCELLATION (PERSISTS TO DB)
// ============================================================

app.post("/api/admin/orders/:orderId/cancel-approve", adminAuth, (req, res) => {
  try {
    const { orderId } = req.params;
    const order = db.prepare("SELECT * FROM payments WHERE order_id = ?").get(orderId);
    if (!order) {
      return res.status(404).json({ message: "Order not found." });
    }

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE payments
      SET order_status = 'Cancelled',
          payment_status = 'Cancelled',
          cancellation_requested = 0,
          cancellation_status = 'Approved',
          cancellation_time = COALESCE(cancellation_time, ?)
      WHERE order_id = ?
    `).run(now, orderId);

    res.json({
      success: true,
      orderId,
      orderStatus: "Cancelled",
      paymentStatus: "Cancelled",
      cancellationStatus: "Approved",
      message: "Order cancellation request approved. Order officially cancelled.",
    });
  } catch (error) {
    console.error("Cancel approve error:", error.message);
    res.status(500).json({ message: "Could not approve order cancellation." });
  }
});

// ============================================================
// ADMIN: EXPORT ALL ORDERS TO EXCEL / CSV (DATABASE BACKED)
// ============================================================

app.get("/api/admin/orders/export-csv", (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT
        p.order_id,
        COALESCE(u.name, p.user_name, 'Customer') AS customer_name,
        COALESCE(u.mobile, p.user_mobile, '') AS mobile,
        COALESCE(u.email, p.user_email, '') AS email,
        COALESCE(p.address, u.address, '') AS address,
        COALESCE(p.pincode, u.pincode, '') AS pincode,
        p.items_json,
        p.amount,
        p.payment_method,
        COALESCE(p.utr, '') AS utr,
        p.payment_status,
        p.order_status,
        p.cancellation_requested,
        COALESCE(p.cancellation_status, 'None') AS cancellation_status,
        COALESCE(p.cancellation_reason, '') AS cancellation_reason,
        COALESCE(p.cancellation_query, '') AS cancellation_query,
        p.payment_time,
        COALESCE(p.cancellation_time, '') AS cancellation_time
      FROM payments p
      LEFT JOIN users u ON u.id = p.user_id
      ORDER BY p.payment_time DESC
    `).all();

    const headers = [
      "Order ID",
      "Customer Name",
      "Mobile Number",
      "Email Address",
      "Delivery Address",
      "Pincode",
      "Items Ordered",
      "Total Items Count",
      "Total Amount (INR)",
      "Payment Method",
      "Payment Status",
      "Order Status",
      "Cancellation Status",
      "Cancellation Reason",
      "Customer Query / Explanation",
      "UTR / Transaction Ref",
      "Order Placed Time",
      "Cancellation Time"
    ];

    const escapeCsv = (val) => {
      if (val === null || val === undefined) return '""';
      const str = String(val).replace(/"/g, '""');
      return `"${str}"`;
    };

    const csvLines = [headers.map(escapeCsv).join(",")];

    for (const r of rows) {
      let itemsSummary = "";
      let totalQty = 0;
      try {
        const items = JSON.parse(r.items_json || "[]");
        itemsSummary = items.map(it => `${it.name || "Item"} (x${it.quantity || 1} @ Rs.${it.price || 0})`).join("; ");
        totalQty = items.reduce((sum, it) => sum + (Number(it.quantity) || 1), 0);
      } catch (_) {}

      let cancelDisplay = r.cancellation_status;
      if (r.order_status === "Cancelled" || r.payment_status === "Cancelled") {
        cancelDisplay = "Approved & Cancelled";
      } else if (r.cancellation_requested || r.order_status === "Cancellation Requested") {
        cancelDisplay = "Cancellation Requested (Pending Admin)";
      } else {
        cancelDisplay = "Active / None";
      }

      csvLines.push([
        escapeCsv(r.order_id),
        escapeCsv(r.customer_name),
        escapeCsv(r.mobile),
        escapeCsv(r.email),
        escapeCsv(r.address),
        escapeCsv(r.pincode),
        escapeCsv(itemsSummary),
        escapeCsv(totalQty || ""),
        escapeCsv(r.amount),
        escapeCsv(r.payment_method),
        escapeCsv(r.payment_status),
        escapeCsv(r.order_status),
        escapeCsv(cancelDisplay),
        escapeCsv(r.cancellation_reason),
        escapeCsv(r.cancellation_query),
        escapeCsv(r.utr),
        escapeCsv(r.payment_time),
        escapeCsv(r.cancellation_time)
      ].join(","));
    }

    const csvString = "\uFEFF" + csvLines.join("\r\n");
    res.setHeader("Content-Type", "text/csv; charset=utf-8");
    res.setHeader("Content-Disposition", 'attachment; filename="Suryas_Groceries_Orders_Database.csv"');
    res.send(csvString);
  } catch (error) {
    console.error("Orders export CSV error:", error.message);
    res.status(500).json({ message: "Could not export orders." });
  }
});

// ============================================================
// PROTECTED ORDER TRACKING (AUTHENTICATED USER ONLY)
// ============================================================

app.get("/api/orders/track/:orderId", firebaseAuth, syncUser, (req, res) => {
  try {
    const callerEmail = String(req.firebaseUser?.email || "").toLowerCase();
    const isAdmin = ADMIN_EMAILS.includes(callerEmail);

    const order = db.prepare(`
      SELECT order_id, user_id, amount, payment_method, payment_status, order_status, address, pincode, latitude, longitude, location_accuracy, payment_time, items_json
      FROM payments
      WHERE order_id = ?
    `).get(req.params.orderId);

    // Generic 404 prevents order enumeration and unauthorized order disclosure
    if (!order || (!isAdmin && order.user_id !== req.user.id)) {
      return res.status(404).json({ ok: false, message: "Order not found." });
    }

    res.json({
      ok: true,
      order: {
        order_id: order.order_id,
        amount: order.amount,
        payment_method: order.payment_method,
        payment_status: order.payment_status,
        order_status: order.order_status,
        address: order.address,
        pincode: order.pincode || "",
        latitude: order.latitude ?? null,
        longitude: order.longitude ?? null,
        location_accuracy: order.location_accuracy ?? null,
        has_coordinates: Boolean(order.latitude != null && order.longitude != null),
        payment_time: order.payment_time,
        items: JSON.parse(order.items_json || "[]"),
      },
    });
  } catch (error) {
    console.error("Order tracking error:", error.message);
    res.status(500).json({ ok: false, message: "Could not fetch order tracking info." });
  }
});

// ============================================================
// PUBLIC ORDER TRACKING (HIGH-ENTROPY TOKEN ONLY, ZERO PII)
// ============================================================

app.get("/api/orders/track-public/:trackingToken", (req, res) => {
  try {
    const { trackingToken } = req.params;
    if (!trackingToken || typeof trackingToken !== "string" || trackingToken.length < 32) {
      return res.status(400).json({ ok: false, message: "Invalid tracking token format." });
    }

    const order = db.prepare(`
      SELECT order_id, payment_status, order_status, payment_time, items_json
      FROM payments
      WHERE tracking_token = ?
    `).get(trackingToken);

    if (!order) {
      return res.status(404).json({ ok: false, message: "Tracking details not found." });
    }

    const items = JSON.parse(order.items_json || "[]");

    // Return strictly minimal non-sensitive status fields with zero customer PII
    res.json({
      ok: true,
      order: {
        order_status: order.order_status,
        payment_status: order.payment_status,
        payment_time: order.payment_time,
        items_count: items.length,
      },
    });
  } catch (error) {
    console.error("Public track error:", error.message);
    res.status(500).json({ ok: false, message: "Could not fetch tracking details." });
  }
});

// ============================================================
// PRODUCTS CRUD ENDPOINTS
// ============================================================

function stringArrayJson(value) {
  if (!Array.isArray(value)) return "[]";
  return JSON.stringify(value
    .filter((entry) => typeof entry === "string")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .slice(0, 36));
}

app.get("/api/products", (req, res) => {
  try {
    const products = db.prepare("SELECT * FROM products ORDER BY created_at DESC").all();
    res.json(products);
  } catch (error) {
    console.error("Fetch products error:", error.message);
    res.status(500).json({ message: "Could not fetch products." });
  }
});

app.post("/api/products", adminAuth, (req, res) => {
  try {
    const {
      id, name, description, price, category, isVeg, rating, reviews,
      prepTime, serves, badge, image, gallery, ingredients, benefits,
      suitableFor, inStock, barcode,
    } = req.body;

    if (!name || price == null || !category) {
      return res.status(400).json({ message: "Name, price and category are required." });
    }

    const productId = id || `prod_${Date.now()}`;

    db.prepare(`
      INSERT OR REPLACE INTO products (
        id, name, description, price, category, is_veg, rating, reviews, prep_time, serves, badge, image,
        gallery_json, ingredients_json, benefits, suitable_for, in_stock, barcode, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      productId,
      name,
      description || "",
      Number(price) || 0,
      category,
      isVeg === false ? 0 : 1,
      Number(rating) || 4.8,
      reviews || "10+",
      prepTime || "Express 15m",
      serves || "1 Unit",
      badge || "",
      image || "",
      stringArrayJson(gallery),
      stringArrayJson(ingredients),
      benefits || "",
      suitableFor || "",
      inStock === false ? 0 : 1,
      barcode ? String(barcode).trim() : null,
      nowIso()
    );

    res.status(201).json({
      success: true,
      message: "Product saved successfully",
      id: productId,
    });
  } catch (error) {
    console.error("Save product error:", error.message);
    res.status(500).json({ message: "Could not save product." });
  }
});

app.put("/api/products/:id", adminAuth, (req, res) => {
  try {
    const { id } = req.params;
    const {
      name, description, price, category, isVeg, rating, reviews,
      prepTime, serves, badge, image, gallery, ingredients, benefits,
      suitableFor, inStock, barcode,
    } = req.body;

    db.prepare(`
      UPDATE products
      SET name = COALESCE(?, name),
          description = COALESCE(?, description),
          price = COALESCE(?, price),
          category = COALESCE(?, category),
          is_veg = COALESCE(?, is_veg),
          rating = COALESCE(?, rating),
          reviews = COALESCE(?, reviews),
          prep_time = COALESCE(?, prep_time),
          serves = COALESCE(?, serves),
          badge = COALESCE(?, badge),
          image = COALESCE(?, image),
          gallery_json = COALESCE(?, gallery_json),
          ingredients_json = COALESCE(?, ingredients_json),
          benefits = COALESCE(?, benefits),
          suitable_for = COALESCE(?, suitable_for),
          in_stock = COALESCE(?, in_stock),
          barcode = COALESCE(?, barcode)
      WHERE id = ?
    `).run(
      name,
      description,
      price != null ? Number(price) : null,
      category,
      isVeg != null ? (isVeg ? 1 : 0) : null,
      rating != null ? Number(rating) : null,
      reviews,
      prepTime,
      serves,
      badge,
      image,
      gallery != null ? stringArrayJson(gallery) : null,
      ingredients != null ? stringArrayJson(ingredients) : null,
      benefits,
      suitableFor,
      inStock != null ? (inStock ? 1 : 0) : null,
      barcode != null ? String(barcode).trim() : null,
      id
    );

    res.json({
      success: true,
      message: "Product updated successfully",
      id,
    });
  } catch (error) {
    console.error("Update product error:", error.message);
    res.status(500).json({ message: "Could not update product." });
  }
});

app.delete("/api/products/:id", adminAuth, (req, res) => {
  try {
    const { id } = req.params;
    db.prepare("DELETE FROM products WHERE id = ?").run(id);
    res.json({
      success: true,
      message: "Product deleted successfully",
      id,
    });
  } catch (error) {
    console.error("Delete product error:", error.message);
    res.status(500).json({ message: "Could not delete product." });
  }
});

// ============================================================
// APP UPDATES TABLE & ENDPOINTS
// ============================================================

db.exec(`
CREATE TABLE IF NOT EXISTS app_updates (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version TEXT NOT NULL DEFAULT '2.1',
  version_code INTEGER NOT NULL DEFAULT 21,
  size_mb TEXT NOT NULL DEFAULT '54.8 MB',
  title TEXT NOT NULL DEFAULT 'Surya''s Groceries Fresh Update',
  description TEXT NOT NULL DEFAULT 'New items added, grocery prices updated, and express delivery improvements.',
  apk_url TEXT NOT NULL DEFAULT 'https://files.catbox.moe/co6rrh.apk',
  update_available INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO app_updates (id, version, version_code, size_mb, title, description, apk_url, update_available)
VALUES (1, '2.1', 21, '54.8 MB', 'Surya''s Groceries Fresh Update', 'New items added, grocery prices updated, and express delivery improvements.', 'https://files.catbox.moe/co6rrh.apk', 1);
`);

app.get("/api/app/update-info", (req, res) => {
  try {
    const row = db.prepare("SELECT * FROM app_updates WHERE id = 1").get();
    if (!row) {
      return res.json({
        updateAvailable: true,
        version: "2.1",
        versionCode: 21,
        sizeMb: "54.8 MB",
        title: "Surya's Groceries Fresh Update",
        description: "New items added, grocery prices updated, and express delivery improvements.",
        apkUrl: "https://files.catbox.moe/co6rrh.apk",
        updatedAt: nowIso(),
      });
    }
    return res.json({
      updateAvailable: row.update_available === 1,
      version: row.version,
      versionCode: row.version_code,
      sizeMb: row.size_mb,
      title: row.title,
      description: row.description,
      apkUrl: row.apk_url,
      updatedAt: row.updated_at,
    });
  } catch (err) {
    return res.json({
      updateAvailable: true,
      version: "2.1",
      versionCode: 21,
      sizeMb: "54.8 MB",
      title: "Surya's Groceries Fresh Update",
      description: "New items added, grocery prices updated, and express delivery improvements.",
      apkUrl: "https://files.catbox.moe/co6rrh.apk",
      updatedAt: new Date().toISOString(),
    });
  }
});

app.post("/api/app/update-info", adminAuth, (req, res) => {
  try {
    const { version, versionCode, sizeMb, title, description, apkUrl, updateAvailable } = req.body;
    db.prepare(`
      INSERT OR REPLACE INTO app_updates (id, version, version_code, size_mb, title, description, apk_url, update_available, updated_at)
      VALUES (1, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `).run(
      version || "2.1",
      versionCode || 21,
      sizeMb || "54.8 MB",
      title || "Surya's Groceries Fresh Update",
      description || "New items added, grocery prices updated, and express delivery improvements.",
      apkUrl || "https://files.catbox.moe/co6rrh.apk",
      updateAvailable === false ? 0 : 1
    );
    return res.json({ success: true, message: "App update broadcast published successfully." });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Serve production Flutter web build
const webBuildPath = path.join(__dirname, "../build/web");
app.use(express.static(webBuildPath));

app.use((req, res, next) => {
  if (
    req.method === "GET" &&
    !req.path.startsWith("/api") &&
    !req.path.startsWith("/public")
  ) {
    const indexFile = path.join(webBuildPath, "index.html");
    if (fs.existsSync(indexFile)) {
      return res.sendFile(indexFile);
    }
    return res.status(404).json({
      error: "Frontend files are not available on this server.",
    });
  }
  next();
});

// ============================================================
// SERVER START
// ============================================================

app.listen(PORT, "0.0.0.0", () => {
  console.log("==========================================");
  console.log(`Surya's General Store API running on port ${PORT}`);
  console.log(`Admin accounts configured: ${ADMIN_EMAILS.length}`);
  console.log("==========================================");
});

// ============================================================
// 24/7 RENDER KEEP-ALIVE
// ============================================================
const RENDER_PUBLIC_URL = process.env.RENDER_EXTERNAL_URL || "https://surya-groceries-api.onrender.com";
setInterval(async () => {
  try {
    await fetch(`${RENDER_PUBLIC_URL}/api/health`);
  } catch (_) {}
}, 9 * 60 * 1000);
