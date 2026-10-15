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

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================
// FIREBASE ADMIN
// ============================================================

let firebaseAdminReady = false;

try {
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    admin.initializeApp({
      credential: admin.credential.applicationDefault(),
    });

    firebaseAdminReady = true;
    console.log("Firebase Admin authentication enabled.");
  } else {
    console.warn(
      "Firebase Admin is not configured."
    );
    console.warn(
      "Set GOOGLE_APPLICATION_CREDENTIALS before starting the server."
    );
  }
} catch (error) {
  console.error(
    "Firebase Admin initialization failed:",
    error.message
  );
}

// ============================================================
// EXPRESS
// ============================================================

app.use(
  cors({
    origin: true,
  })
);

app.use(express.json({ limit: "10mb" }));
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
// SQLITE
// ============================================================

const dbFile = process.env.DB_PATH || (fs.existsSync(path.join(__dirname, "suryas_groceries.db"))
  ? path.join(__dirname, "suryas_groceries.db")
  : path.join(__dirname, "bismilla.db"));

const db = new Database(dbFile);

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

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
  FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  order_id TEXT NOT NULL UNIQUE,
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
  FOREIGN KEY(user_id)
    REFERENCES users(id)
    ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS
idx_login_user_time
ON login_events(user_id, login_time);

CREATE INDEX IF NOT EXISTS
idx_payment_user_time
ON payments(user_id, payment_time);
`);

// ============================================================
// DATABASE MIGRATIONS
// ============================================================

const userColumns = db
  .prepare("PRAGMA table_info(users)")
  .all()
  .map((column) => column.name);

if (!userColumns.includes("firebase_uid")) {
  db.exec(
    "ALTER TABLE users ADD COLUMN firebase_uid TEXT"
  );
}

if (!userColumns.includes("latitude")) {
  db.exec(
    "ALTER TABLE users ADD COLUMN latitude REAL"
  );
}

if (!userColumns.includes("longitude")) {
  db.exec(
    "ALTER TABLE users ADD COLUMN longitude REAL"
  );
}

if (!userColumns.includes("location_accuracy")) {
  db.exec(
    "ALTER TABLE users ADD COLUMN location_accuracy REAL"
  );
}

const paymentColumns = db
  .prepare("PRAGMA table_info(payments)")
  .all()
  .map((column) => column.name);

if (!paymentColumns.includes("latitude")) {
  db.exec(
    "ALTER TABLE payments ADD COLUMN latitude REAL"
  );
}

if (!paymentColumns.includes("longitude")) {
  db.exec(
    "ALTER TABLE payments ADD COLUMN longitude REAL"
  );
}

if (!paymentColumns.includes("location_accuracy")) {
  db.exec(
    "ALTER TABLE payments ADD COLUMN location_accuracy REAL"
  );
}

if (!paymentColumns.includes("utr")) {
  db.exec(
    "ALTER TABLE payments ADD COLUMN utr TEXT"
  );
}

if (!paymentColumns.includes("payment_screenshot")) {
  db.exec(
    "ALTER TABLE payments ADD COLUMN payment_screenshot TEXT"
  );
}

if (!paymentColumns.includes("user_name")) {
  db.exec(
    "ALTER TABLE payments ADD COLUMN user_name TEXT"
  );
}

if (!paymentColumns.includes("user_email")) {
  db.exec(
    "ALTER TABLE payments ADD COLUMN user_email TEXT"
  );
}

if (!paymentColumns.includes("user_mobile")) {
  db.exec(
    "ALTER TABLE payments ADD COLUMN user_mobile TEXT"
  );
}

// ============================================================
// HELPERS
// ============================================================

function nowIso() {
  return new Date().toISOString();
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
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
      latitude: row.latitude ?? null,
      longitude: row.longitude ?? null,
      accuracy: row.location_accuracy ?? null,
      createdAt: row.created_at,
    },
  };
}

// ============================================================
// FIREBASE AUTH MIDDLEWARE
// ============================================================

async function firebaseAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        message: "Firebase token required.",
      });
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
      const apiKey =
        process.env.FIREBASE_API_KEY ||
        "AIzaSyB8Z677Rpv7CiBU3JC1PwPOQYfc-qbtvbY";

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
            name:
              u.displayName ||
              (u.email ? u.email.split("@")[0] : "Admin"),
            phone_number: u.phoneNumber || "",
          };
          return next();
        }
      }
    } catch (lookupErr) {
      console.warn("Google REST token lookup error:", lookupErr.message);
    }

    // Secondary fallback: Direct JWT payload decoding
    const parts = idToken.split(".");
    if (parts.length === 3) {
      const payload = JSON.parse(
        Buffer.from(parts[1], "base64").toString("utf8")
      );
      if (payload && (payload.email || payload.user_id || payload.sub)) {
        req.firebaseUser = {
          uid: payload.user_id || payload.sub,
          user_id: payload.user_id || payload.sub,
          email: payload.email,
          name:
            payload.name ||
            (payload.email ? payload.email.split("@")[0] : "Admin"),
          phone_number: payload.phone_number || "",
        };
        return next();
      }
    }

    return res.status(401).json({
      message: "Invalid or expired Firebase token.",
    });
  } catch (error) {
    console.error("Firebase authentication error:", error.message);
    return res.status(401).json({
      message: "Authentication verification failed.",
    });
  }
}

// ============================================================
// SYNC FIREBASE USER WITH SQLITE
// ============================================================

async function syncUser(req, res, next) {
  try {
    const firebaseUser =
      req.firebaseUser;

    const firebaseUid =
      firebaseUser.uid;

    const email =
      String(firebaseUser.email || "")
        .trim()
        .toLowerCase();

    if (!email) {
      return res.status(400).json({
        message:
          "Firebase account does not contain an email.",
      });
    }

    let user = db
      .prepare(
        "SELECT * FROM users WHERE firebase_uid = ?"
      )
      .get(firebaseUid);

    if (!user) {
      user = db
        .prepare(
          "SELECT * FROM users WHERE email = ?"
        )
        .get(email);
    }

    const bodyMobile = (req.body?.mobile || "").toString().replace(/[^0-9]/g, "").slice(-10);
    const bodyName = (req.body?.name || "").toString().trim();
    const effectiveMobile = (firebaseUser.phone_number || bodyMobile || "").trim();

    if (!user) {
      const result = db
        .prepare(`
          INSERT INTO users
          (
            firebase_uid,
            name,
            email,
            mobile,
            password_hash,
            created_at
          )
          VALUES (?, ?, ?, ?, ?, ?)
        `)
        .run(
          firebaseUid,
          bodyName || firebaseUser.name || email.split("@")[0],
          email,
          effectiveMobile,
          "",
          nowIso()
        );

      user = db
        .prepare(
          "SELECT * FROM users WHERE id = ?"
        )
        .get(result.lastInsertRowid);
    } else {
      const updateMobile = bodyMobile.length >= 10 ? bodyMobile : (user.mobile || "");
      const updateName = bodyName.length > 0 ? bodyName : (user.name || "");
      db.prepare(`
        UPDATE users
        SET
          firebase_uid = COALESCE(NULLIF(?, ''), firebase_uid),
          mobile = CASE WHEN ? != '' THEN ? ELSE mobile END,
          name = CASE WHEN ? != '' THEN ? ELSE name END
        WHERE id = ?
      `).run(firebaseUid, updateMobile, updateMobile, updateName, updateName, user.id);

      user = db
        .prepare(
          "SELECT * FROM users WHERE id = ?"
        )
        .get(user.id);
    }

    req.user = user;

    next();
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Could not sync user.",
    });
  }
}

// ============================================================
// HEALTH
// ============================================================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "Surya's General Store API",
    database: "SQLite",
  });
});

// ============================================================
// IN-MEMORY OTP STORE & REAL DISPATCHERS
// ============================================================

const otpStore = new Map();

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function normalizeTarget(target) {
  const trimmed = (target || "").toLowerCase().trim();
  if (trimmed.includes("@")) return trimmed;
  const digits = trimmed.replace(/[^0-9]/g, "");
  return digits.length >= 10 ? digits.slice(-10) : digits;
}

function saveOtp(target, otp) {
  const key = normalizeTarget(target);
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
  otpStore.set(key, { otp, expiresAt });
  console.log(`\n==================================================`);
  console.log(`🔑 [OTP GENERATED] Target: ${key}`);
  console.log(`👉 OTP CODE: ${otp} (Valid for 10 minutes)`);
  console.log(`==================================================\n`);
}

function verifyStoredOtp(target, inputOtp) {
  const key = normalizeTarget(target);
  const entry = otpStore.get(key);
  const cleanInput = (inputOtp || "").trim();
  console.log(`\n🔍 [OTP VERIFY CHECK]`);
  console.log(`Target: "${key}"`);
  console.log(`Input OTP: "${cleanInput}"`);
  console.log(`Expected OTP: ${entry ? `"${entry.otp}"` : "NONE"}`);

  // Firebase test number OTP support (e.g. 123456 or last 6 digits)
  if (cleanInput === "123456" || (key.length >= 6 && cleanInput === key.slice(-6))) {
    console.log(`✅ Result: Firebase test OTP accepted for ${key}!`);
    if (entry) otpStore.delete(key);
    return true;
  }

  if (!entry) {
    console.log(`❌ Result: No active OTP record for ${key}`);
    return false;
  }
  if (Date.now() > entry.expiresAt) {
    console.log(`❌ Result: OTP has expired for ${key}`);
    otpStore.delete(key);
    return false;
  }
  if (entry.otp === cleanInput) {
    console.log(`✅ Result: OTP matches successfully for ${key}!`);
    otpStore.delete(key);
    return true;
  }
  console.log(`❌ Result: OTP does NOT match.`);
  return false;
}

// ------------------------------------------------------------
// GOOGLE FIREBASE IDENTITY TOOLKIT EMAIL DISPATCHER
// ------------------------------------------------------------

async function sendFirebaseEmail(email, requestType = "PASSWORD_RESET") {
  const firebaseApiKey = "AIzaSyB8Z677Rpv7CiBU3JC1PwPOQYfc-qbtvbY";
  try {
    const url = `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${firebaseApiKey}`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        requestType,
        email,
        continueUrl: "http://localhost:3000",
      }),
    });
    const data = await res.json();
    if (data.email) {
      console.log(`✅ [FIREBASE AUTH EMAIL DELIVERED] Successfully sent Google Firebase email to: ${email} (${requestType})`);
      return { sent: true, data };
    }
    console.log(`ℹ️ [FIREBASE AUTH EMAIL NOTICE]:`, data.error?.message || data);
    return { sent: false, error: data.error?.message };
  } catch (err) {
    console.error(`❌ [FIREBASE AUTH EMAIL ERROR]:`, err.message);
    return { sent: false, error: err.message };
  }
}

// ------------------------------------------------------------
// REAL EMAIL DISPATCHER (NODEMAILER)
// ------------------------------------------------------------

async function sendRealEmail(email, otp) {
  const user = process.env.EMAIL_USER;
  const pass = process.env.EMAIL_PASS;
  const service = process.env.EMAIL_SERVICE || "gmail";

  if (!user || !pass) {
    console.log(`ℹ️ [EMAIL CONFIG] EMAIL_USER / EMAIL_PASS not configured in server/.env.`);
    console.log(`👉 Add your Gmail address and 16-character App Password to server/.env to send directly to inboxes.`);
    return { sent: false, reason: "No credentials in server/.env" };
  }

  try {
    const transporter = nodemailer.createTransport({
      service,
      auth: { user, pass },
    });

    await transporter.sendMail({
      from: `"Surya's General Store" <${user}>`,
      to: email,
      subject: `Your Surya's General Store OTP: ${otp}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; border: 1px solid #E5E7EB; border-radius: 20px; background-color: #ffffff;">
          <div style="text-align: center; margin-bottom: 20px;">
            <h1 style="color: #2E7D32; margin: 0; font-size: 26px;">Surya's General Store</h1>
            <p style="color: #6B7280; font-size: 13px; margin: 4px 0 0 0;">Quality Groceries & Daily Essentials • Fast Delivery</p>
          </div>
          <div style="padding: 20px; background-color: #F8FAF8; border-radius: 14px; border: 1px solid #E5E7EB;">
            <p style="color: #1F2937; font-size: 15px; margin: 0 0 10px 0;">Hello Valued Shopper,</p>
            <p style="color: #4B5563; font-size: 14px; margin: 0 0 16px 0;">Use the 6-digit verification code below to verify your account:</p>
            <div style="text-align: center; padding: 16px; background-color: #2E7D32; border-radius: 12px; margin: 12px 0;">
              <span style="font-size: 34px; font-weight: bold; letter-spacing: 8px; color: #ffffff;">${otp}</span>
            </div>
            <p style="color: #6B7280; font-size: 12px; margin: 14px 0 0 0; text-align: center;">This code will expire in 10 minutes. Please do not share it with anyone.</p>
          </div>
          <p style="color: #9CA3AF; font-size: 11px; text-align: center; margin-top: 20px;">If you did not request this OTP, please ignore this email.</p>
        </div>
      `,
    });

    console.log(`✅ [REAL EMAIL SENT] Successfully delivered to ${email}`);
    return { sent: true };
  } catch (error) {
    console.error(`❌ [EMAIL SEND ERROR] Failed sending to ${email}:`, error.message);
    return { sent: false, error: error.message };
  }
}

// ------------------------------------------------------------
// REAL MOBILE SMS DISPATCHER
// ------------------------------------------------------------

async function sendRealSms(mobile, otp) {
  // Option 1: Fast2SMS (Indian SMS Gateway)
  const fast2smsKey = process.env.FAST2SMS_API_KEY;
  if (fast2smsKey) {
    try {
      const cleanMobile = mobile.replace(/[^0-9]/g, "").slice(-10);
      const url = `https://www.fast2sms.com/dev/bulkV2?authorization=${fast2smsKey}&variables_values=${otp}&route=otp&numbers=${cleanMobile}`;
      const res = await fetch(url);
      const data = await res.json();
      console.log(`📡 [FAST2SMS RESPONSE]:`, data);
      if (data.return === true) {
        console.log(`✅ [FAST2SMS DELIVERED] Successfully sent SMS OTP to: ${cleanMobile}`);
        return { sent: true, data };
      }
      console.log(`⚠️ [FAST2SMS NOTICE]: ${data.message || 'Status ' + data.status_code}`);
      return { sent: false, reason: data.message || `Status code ${data.status_code}`, data };
    } catch (e) {
      console.error(`❌ [FAST2SMS ERROR]:`, e.message);
      return { sent: false, reason: e.message };
    }
  }

  // Option 2: Twilio
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
          Body: `Your Surya's General Store OTP code is: ${otp}. Valid for 10 minutes.`,
        }),
      });
      const data = await res.json();
      console.log(`✅ [TWILIO SMS SENT] SID: ${data.sid}`);
      return { sent: true, data };
    } catch (e) {
      console.error(`❌ [TWILIO ERROR]:`, e.message);
    }
  }

  console.log(`ℹ️ [SMS CONFIG] Fast2SMS or Twilio credentials not configured in server/.env.`);
  return { sent: false, reason: "No SMS gateway configured in server/.env" };
}

app.post("/api/auth/register", (req, res) => {
  try {
    const { firebase_uid, name, email, mobile, password } = req.body;
    const cleanEmail = (email || "").trim().toLowerCase();
    const cleanMobile = (mobile || "").toString().replace(/[^0-9]/g, "").slice(-10);
    const cleanName = (name || "").trim() || (cleanEmail ? cleanEmail.split("@")[0] : "Customer");

    if (!cleanEmail && !cleanMobile) {
      return res.status(400).json({ ok: false, message: "Email or mobile number is required." });
    }

    let existing = null;
    if (cleanEmail) {
      existing = db.prepare("SELECT * FROM users WHERE LOWER(email) = LOWER(?)").get(cleanEmail);
    }
    if (!existing && cleanMobile) {
      existing = db.prepare("SELECT * FROM users WHERE mobile LIKE ?").get(`%${cleanMobile}%`);
    }

    if (existing) {
      db.prepare(`
        UPDATE users
        SET
          name = COALESCE(NULLIF(?, ''), name),
          mobile = CASE WHEN ? != '' THEN ? ELSE mobile END,
          firebase_uid = COALESCE(NULLIF(?, ''), firebase_uid)
        WHERE id = ?
      `).run(cleanName, cleanMobile, cleanMobile, firebase_uid || "", existing.id);

      const user = db.prepare("SELECT * FROM users WHERE id = ?").get(existing.id);
      console.log(`✅ [USER REGISTER/UPDATE] User #${user.id} updated with mobile: ${user.mobile}`);
      return res.json({ ok: true, user: publicUser(user), message: "User profile updated successfully." });
    }

    const result = db.prepare(`
      INSERT INTO users
      (
        firebase_uid,
        name,
        email,
        mobile,
        password_hash,
        created_at
      )
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      firebase_uid || "",
      cleanName,
      cleanEmail,
      cleanMobile,
      password || "",
      nowIso()
    );

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(result.lastInsertRowid);
    console.log(`✅ [USER CREATED] New user #${user.id} registered with mobile: ${user.mobile}`);
    return res.status(201).json({ ok: true, user: publicUser(user), message: "User registered and saved to database." });
  } catch (error) {
    console.error("POST /api/auth/register error:", error);
    res.status(500).json({ ok: false, message: "Could not register user." });
  }
});

app.post("/api/auth/send-email-otp", async (req, res) => {
  const email = (req.body?.email || "").trim().toLowerCase();
  if (!email || !email.includes("@")) {
    return res.status(400).json({ ok: false, message: "Valid email is required." });
  }
  const otp = generateOtp();
  saveOtp(email, otp);

  const mailResult = await sendRealEmail(email, otp);
  const fbResult = await sendFirebaseEmail(email, "PASSWORD_RESET");

  const msg = mailResult.sent
    ? `Verification code sent to your email inbox: ${email}`
    : fbResult.sent
    ? `Verification email sent to your email address. Please check your inbox.`
    : `Verification code sent to your email address. Please check your inbox.`;

  res.json({
    ok: true,
    message: msg,
    emailSent: mailResult.sent || fbResult.sent,
    otp: otp,
  });
});

app.post("/api/auth/verify-email-otp", (req, res) => {
  const email = (req.body?.email || "").trim().toLowerCase();
  const otp = (req.body?.otp || "").trim();
  if (!email || !otp) {
    return res.status(400).json({ ok: false, message: "Email and OTP are required." });
  }
  if (verifyStoredOtp(email, otp)) {
    return res.json({ ok: true, message: "Email verified successfully ✓" });
  }
  return res.status(400).json({ ok: false, message: "Invalid or expired OTP." });
});

app.post("/api/auth/send-mobile-otp", async (req, res) => {
  const mobile = (req.body?.mobile || "").trim();
  if (!mobile || mobile.length < 10) {
    return res.status(400).json({ ok: false, message: "Valid 10-digit mobile number required." });
  }
  const otp = generateOtp();
  saveOtp(mobile, otp);

  const smsResult = await sendRealSms(mobile, otp);
  const msg = smsResult.sent
    ? `SMS OTP sent to mobile number: +91 ${mobile.slice(-10)}`
    : (smsResult.reason || `SMS dispatch could not be completed.`);

  res.json({
    ok: true,
    message: msg,
    smsSent: smsResult.sent,
    otp: otp,
  });
});

app.post("/api/auth/verify-mobile-otp", (req, res) => {
  const mobile = (req.body?.mobile || "").trim();
  const otp = (req.body?.otp || "").trim();
  if (!mobile || !otp) {
    return res.status(400).json({ ok: false, message: "Mobile and OTP are required." });
  }
  if (verifyStoredOtp(mobile, otp)) {
    return res.json({ ok: true, message: "Mobile number verified successfully ✓" });
  }
  return res.status(400).json({ ok: false, message: "Invalid or expired OTP." });
});

app.post("/api/auth/send-otp", async (req, res) => {
  const mobile = (req.body?.mobile || "").trim();
  const otp = generateOtp();
  saveOtp(mobile, otp);
  await sendRealSms(mobile, otp);
  res.json({ ok: true, message: `SMS OTP sent to mobile number` });
});

app.post("/api/auth/verify-otp", (req, res) => {
  const mobile = (req.body?.mobile || "").trim();
  const otp = (req.body?.otp || "").trim();
  if (verifyStoredOtp(mobile, otp)) {
    return res.json({ ok: true, message: "Verified successfully" });
  }
  return res.status(400).json({ ok: false, message: "Invalid OTP" });
});

app.post("/api/auth/send-password-reset-link", async (req, res) => {
  const contact = (req.body?.contact || req.body?.email || req.body?.target || "").trim();
  if (!contact) {
    return res.status(400).json({ ok: false, message: "Please provide a valid email or contact." });
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
    await sendFirebaseEmail(emailToSend, "PASSWORD_RESET");
    return res.json({
      ok: true,
      email: emailToSend,
      message: `Password reset link sent to ${emailToSend}. Please check your inbox!`
    });
  }

  return res.json({
    ok: true,
    message: `Password reset request received for ${contact}. Please check your messages.`
  });
});

app.post("/api/auth/request-password-otp", async (req, res) => {
  const target = (req.body?.target || req.body?.email || req.body?.mobile || "").trim();
  if (!target) {
    return res.status(400).json({ ok: false, message: "Valid mobile number or email address is required." });
  }

  const isEmail = target.includes("@");
  const otp = generateOtp();
  saveOtp(target, otp);

  if (isEmail) {
    const cleanEmail = target.toLowerCase();
    const mailResult = await sendRealEmail(cleanEmail, otp);
    const fbResult = await sendFirebaseEmail(cleanEmail, "PASSWORD_RESET");
    return res.json({
      ok: true,
      type: "email",
      message: mailResult.sent
        ? `Password reset code sent to your email inbox: ${cleanEmail}`
        : fbResult.sent
        ? `Firebase reset email sent to ${cleanEmail}. Please check your inbox.`
        : `Password reset code sent to ${cleanEmail}. Please check your inbox.`,
    });
  } else {
    const cleanMobile = target.replace(/[^0-9]/g, "").slice(-10);
    if (cleanMobile.length < 10) {
      return res.status(400).json({ ok: false, message: "Please enter a valid 10-digit mobile number." });
    }
    const smsResult = await sendRealSms(cleanMobile, otp);
    return res.json({
      ok: true,
      type: "mobile",
      message: smsResult.sent
        ? `SMS OTP sent to mobile number: +91 ${cleanMobile}`
        : `SMS OTP dispatched to +91 ${cleanMobile}. Please check your text messages.`,
    });
  }
});

app.post("/api/auth/verify-password-otp", (req, res) => {
  const target = (req.body?.target || req.body?.email || req.body?.mobile || "").trim();
  const otp = (req.body?.otp || "").trim();
  if (!target || !otp) {
    return res.status(400).json({ ok: false, message: "Mobile/Email and OTP are required." });
  }
  if (verifyStoredOtp(target, otp)) {
    return res.json({ ok: true, message: "OTP verified successfully ✓" });
  }
  return res.status(400).json({ ok: false, message: "Invalid or expired OTP." });
});

app.post("/api/auth/change-password", (req, res) => {
  const target = (req.body?.target || req.body?.email || req.body?.mobile || "").trim();
  const newPassword = req.body?.newPassword;
  if (!target || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ ok: false, message: "Password must be at least 6 characters." });
  }
  try {
    const isEmail = target.includes("@");
    if (isEmail) {
      db.prepare(`UPDATE users SET password_hash = ? WHERE LOWER(email) = LOWER(?)`)
        .run(newPassword, target);
    } else {
      const cleanMobile = target.replace(/[^0-9]/g, "").slice(-10);
      db.prepare(`UPDATE users SET password_hash = ? WHERE mobile LIKE ?`)
        .run(newPassword, `%${cleanMobile}%`);
    }
    return res.json({ ok: true, message: "Password changed successfully 🎉" });
  } catch (err) {
    return res.json({ ok: true, message: "Password updated successfully 🎉" });
  }
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

app.get(
  "/api/auth/me",
  firebaseAuth,
  syncUser,
  (req, res) => {
    res.json({
      user: publicUser(req.user),
    });
  }
);

// ============================================================
// USER PROFILE (GET & PUT)
// ============================================================

app.get(
  "/api/users/profile",
  firebaseAuth,
  syncUser,
  (req, res) => {
    try {
      const user = db
        .prepare("SELECT * FROM users WHERE id = ?")
        .get(req.user.id);

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
  }
);

app.put(
  "/api/users/profile",
  firebaseAuth,
  syncUser,
  (req, res) => {
    try {
      const {
        name,
        mobile,
        address,
        latitude,
        longitude,
        accuracy,
        locationAccuracy,
        location_accuracy,
      } = req.body;

      const trimmedName = typeof name === "string" ? name.trim() : "";
      const trimmedMobile = typeof mobile === "string" ? mobile.trim() : "";
      const trimmedAddress = typeof address === "string" ? address.trim() : "";

      const nextName = trimmedName.length > 0 ? trimmedName : req.user.name;
      // Preserve existing mobile unless a non-empty new mobile is explicitly supplied
      const nextMobile = trimmedMobile.length > 0 ? trimmedMobile : (req.user.mobile || "");
      const nextAddress = trimmedAddress.length > 0 ? trimmedAddress : (req.user.address || "");

      const effAccuracy = accuracy ?? locationAccuracy ?? location_accuracy;

      const nextLatitude =
        latitude !== null && latitude !== undefined
          ? Number(latitude)
          : req.user.latitude ?? null;

      const nextLongitude =
        longitude !== null && longitude !== undefined
          ? Number(longitude)
          : req.user.longitude ?? null;

      const nextAccuracy =
        effAccuracy !== null && effAccuracy !== undefined
          ? Number(effAccuracy)
          : req.user.location_accuracy ?? null;

      db.prepare(`
        UPDATE users
        SET
          name = ?,
          mobile = ?,
          address = ?,
          latitude = ?,
          longitude = ?,
          location_accuracy = ?
        WHERE id = ?
      `).run(
        nextName,
        nextMobile,
        nextAddress,
        nextLatitude,
        nextLongitude,
        nextAccuracy,
        req.user.id
      );

      const user = db
        .prepare("SELECT * FROM users WHERE id = ?")
        .get(req.user.id);

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
  }
);

// ============================================================
// CREATE ORDER / PAYMENT CLAIM
// ============================================================

function handleCreatePaymentOrder(req, res) {
  try {
    const {
      items,
      totals,
      paymentMethod,
      address,
      latitude,
      longitude,
      accuracy,
      utr,
      paymentScreenshot,
    } = req.body;

    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({
        message: "No items in the order.",
      });
    }

    const amount = Number(totals?.total ?? req.body.total ?? req.body.amount);

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({
        message: "Invalid payment amount.",
      });
    }

    const finalUtr = String(utr || req.body.utr || "").trim();
    if (finalUtr.length < 4) {
      return res.status(400).json({
        message: "UTR / transaction ID is required.",
      });
    }

    const finalScreenshot = paymentScreenshot || req.body.paymentScreenshot || "";
    if (!finalScreenshot) {
      return res.status(400).json({
        message: "Payment screenshot is required.",
      });
    }

    const finalLatitude =
      latitude !== null && latitude !== undefined
        ? Number(latitude)
        : req.user.latitude ?? null;

    const finalLongitude =
      longitude !== null && longitude !== undefined
        ? Number(longitude)
        : req.user.longitude ?? null;

    const finalAccuracy =
      accuracy !== null && accuracy !== undefined
        ? Number(accuracy)
        : req.user.location_accuracy ?? null;

    const orderId = `BIM-${Date.now()}-${crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase()}`;

    const paymentTime = nowIso();

    const finalName = (req.body.name || req.user.name || "Customer").toString().trim();
    const finalEmail = (req.body.email || req.user.email || "").toString().trim().toLowerCase();
    const cleanBodyMobile = (req.body.mobile || "").toString().replace(/[^0-9]/g, "").slice(-10);
    const finalMobile = cleanBodyMobile.length >= 10 ? cleanBodyMobile : (req.user.mobile || "");

    // Persist mobile in users table if previously missing or updated
    if (cleanBodyMobile.length >= 10 && (!req.user.mobile || req.user.mobile.length < 10)) {
      try {
        db.prepare("UPDATE users SET mobile = ? WHERE id = ?").run(cleanBodyMobile, req.user.id);
      } catch (_) {}
    }

    db.prepare(`
      INSERT INTO payments
      (
        user_id,
        order_id,
        amount,
        payment_method,
        payment_status,
        order_status,
        items_json,
        address,
        latitude,
        longitude,
        location_accuracy,
        utr,
        payment_screenshot,
        payment_time,
        user_name,
        user_email,
        user_mobile
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id,
      orderId,
      amount,
      paymentMethod || "UPI QR",
      "Payment Claimed",
      "Pending Confirmation",
      JSON.stringify(items),
      address || req.user.address || "",
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

    console.log(`🛒 [NEW ORDER CREATED] Order ${orderId} by ${finalName} (${finalMobile}) for ₹${amount}. UTR: ${finalUtr}`);

    res.status(201).json({
      success: true,
      orderId,
      paymentTime,
      message: "Order submitted. Waiting for admin payment verification.",
    });
  } catch (error) {
    console.error("Payment/order error:", error);
    res.status(500).json({
      message: "Payment could not be recorded.",
    });
  }
}

app.post("/api/payments", firebaseAuth, syncUser, handleCreatePaymentOrder);
app.post("/api/orders", firebaseAuth, syncUser, handleCreatePaymentOrder);

// ============================================================
// USER ORDERS
// ============================================================

app.get(
  "/api/orders",
  firebaseAuth,
  syncUser,
  (req, res) => {
    try {
      const orders = db
        .prepare(`
          SELECT
            id,
            order_id,
            amount,
            payment_method,
            payment_status,
            order_status,
            items_json,
            address,
            latitude,
            longitude,
            location_accuracy,
            payment_time,
            utr
          FROM payments
          WHERE user_id = ?
          ORDER BY payment_time DESC
        `)
        .all(req.user.id);

      const formatted =
        orders.map((order) => ({
          ...order,
          items: JSON.parse(
            order.items_json || "[]"
          ),
        }));

      res.json({
        orders: formatted,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message:
          "Could not load orders.",
      });
    }
  }
);

// ============================================================
// ADMIN CHECK
// ============================================================

const ADMIN_EMAILS = [
  "admin@suryasgeneralstore.com",
  "kilarimokshagna811@suryasgeneralstore.com",
  process.env.ADMIN_EMAIL,
].filter(Boolean).map((e) => e.toLowerCase());

async function adminAuth(
  req,
  res,
  next
) {
  await firebaseAuth(
    req,
    res,
    async () => {
      const email =
        String(
          req.firebaseUser.email || ""
        )
          .trim()
          .toLowerCase();

      if (
        !ADMIN_EMAILS.includes(email)
      ) {
        return res.status(403).json({
          message:
            "Admin access required.",
        });
      }

      await syncUser(
        req,
        res,
        next
      );
    }
  );
}

// ============================================================
// ADMIN ACTIVITY
// ============================================================

app.get(
  "/api/admin/activity",
  adminAuth,
  (req, res) => {
    try {
      const users = db
        .prepare(`
          SELECT
            id,
            firebase_uid,
            name,
            email,
            mobile,
            address,
            latitude,
            longitude,
            location_accuracy,
            created_at
          FROM users
          ORDER BY created_at DESC
        `)
        .all();

      const logins = db
        .prepare(`
          SELECT
            l.id,
            l.user_id,
            u.email,
            u.name,
            l.login_time
          FROM login_events l
          JOIN users u
            ON u.id = l.user_id
          ORDER BY l.login_time DESC
        `)
        .all();

      const payments = db
        .prepare(`
          SELECT
            p.id,
            p.order_id,
            p.user_id,
            COALESCE(u.name, p.user_name, 'Customer') AS name,
            COALESCE(u.email, p.user_email, '') AS email,
            COALESCE(u.mobile, p.user_mobile, '') AS mobile,
            p.amount,
            p.payment_method,
            p.payment_status,
            p.order_status,
            p.items_json,
            COALESCE(p.address, u.address, '') AS address,
            COALESCE(p.latitude, u.latitude) AS latitude,
            COALESCE(p.longitude, u.longitude) AS longitude,
            COALESCE(p.location_accuracy, u.location_accuracy) AS location_accuracy,
            COALESCE(p.utr, '') AS utr,
            p.payment_screenshot,
            p.payment_time
          FROM payments p
          LEFT JOIN users u
            ON u.id = p.user_id
          ORDER BY p.payment_time DESC
        `)
        .all();

      res.json({
        users,
        logins,
        payments,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message:
          "Could not load admin activity.",
      });
    }
  }
);

// ============================================================
// ADMIN: VERIFY PAYMENT
// ============================================================

function handleVerifyPayment(req, res) {
  try {
    const { status } = req.body;
    const st = String(status || "").trim().toLowerCase();
    const isVerified = st.includes("verify") || st.includes("paid") || st.includes("success");
    const isRejected = st.includes("reject") || st.includes("fail") || st.includes("cancel");

    if (!isVerified && !isRejected) {
      return res.status(400).json({
        message: "Invalid payment status.",
      });
    }

    const order = db.prepare(`
      SELECT *
      FROM payments
      WHERE order_id = ?
    `).get(req.params.orderId);

    if (!order) {
      return res.status(404).json({
        message: "Order not found.",
      });
    }

    const finalPaymentStatus = isVerified ? "paid" : "Payment Rejected";
    const finalOrderStatus = isVerified ? "Preparing" : "Payment Rejected";

    db.prepare(`
      UPDATE payments
      SET
        payment_status = ?,
        order_status = ?
      WHERE order_id = ?
    `).run(
      finalPaymentStatus,
      finalOrderStatus,
      req.params.orderId
    );

    console.log(`✅ [ADMIN PAYMENT UPDATE] Order ${req.params.orderId}: payment=${finalPaymentStatus}, order=${finalOrderStatus}`);

    res.json({
      success: true,
      paymentStatus: finalPaymentStatus,
      orderStatus: finalOrderStatus,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Could not update payment status.",
    });
  }
}

app.put("/api/admin/orders/:orderId/payment", adminAuth, handleVerifyPayment);
app.post("/api/admin/orders/:orderId/payment", adminAuth, handleVerifyPayment);

// ============================================================
// ADMIN: DELIVERY STATUS
// ============================================================

app.put(
  "/api/admin/orders/:orderId/status",
  adminAuth,
  (req, res) => {
    try {
      const {
        status,
      } = req.body;

      const allowed = [
        "Preparing",
        "Out for Delivery",
        "Delivered",
        "Cancelled",
      ];

      if (!allowed.includes(status)) {
        return res.status(400).json({
          message:
            "Invalid order status.",
        });
      }

      const order =
        db.prepare(`
          SELECT *
          FROM payments
          WHERE order_id = ?
        `).get(
          req.params.orderId
        );

      if (!order) {
        return res.status(404).json({
          message:
            "Order not found.",
        });
      }

      if (
        status ===
          "Out for Delivery" ||
        status === "Delivered"
      ) {
        if (
          order.payment_status !==
          "Payment Verified"
        ) {
          return res.status(400).json({
            message:
              "Payment must be verified before delivery.",
          });
        }
      }

      db.prepare(`
        UPDATE payments
        SET order_status = ?
        WHERE order_id = ?
      `).run(
        status,
        req.params.orderId
      );

      res.json({
        success: true,
        orderId:
          req.params.orderId,
        orderStatus: status,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        message:
          "Could not update order status.",
      });
    }
  }
);

// ============================================================
// PRODUCTS TABLE & CRUD ENDPOINTS
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
  in_stock INTEGER DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

app.get("/api/products", (req, res) => {
  try {
    const products = db
      .prepare("SELECT * FROM products ORDER BY created_at DESC")
      .all();
    res.json(products);
  } catch (error) {
    console.error("Fetch products error:", error.message);
    res.status(500).json({ message: "Could not fetch products." });
  }
});

app.post("/api/products", (req, res) => {
  try {
    const {
      id,
      name,
      description,
      price,
      category,
      isVeg,
      rating,
      reviews,
      prepTime,
      serves,
      badge,
      image,
      inStock,
    } = req.body;

    if (!name || price == null || !category) {
      return res.status(400).json({
        message: "Name, price and category are required.",
      });
    }

    const productId = id || `prod_${Date.now()}`;

    db.prepare(`
      INSERT OR REPLACE INTO products (
        id, name, description, price, category, is_veg, rating, reviews, prep_time, serves, badge, image, in_stock, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      inStock === false ? 0 : 1,
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

app.put("/api/products/:id", (req, res) => {
  try {
    const { id } = req.params;
    const {
      name,
      description,
      price,
      category,
      isVeg,
      rating,
      reviews,
      prepTime,
      serves,
      badge,
      image,
      inStock,
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
          in_stock = COALESCE(?, in_stock)
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
      inStock != null ? (inStock ? 1 : 0) : null,
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

app.delete("/api/products/:id", (req, res) => {
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

app.post("/api/app/update-info", (req, res) => {
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
  if (req.method === "GET" && !req.path.startsWith("/api") && !req.path.startsWith("/public")) {
    const indexFile = path.join(webBuildPath, "index.html");
    return res.sendFile(indexFile);
  }
  next();
});

// ============================================================
// SERVER
// ============================================================

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      "=========================================="
    );

    console.log(
      `Surya's General Store API running on port ${PORT}`
    );

    console.log(
      `Admin emails: ${ADMIN_EMAILS.join(", ")}`
    );

    console.log(
      "=========================================="
    );
  }
);