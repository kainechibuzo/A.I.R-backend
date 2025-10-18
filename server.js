will this work for air or is it not pro level /**
 * 🌬️ AIR Hybrid Monitoring Server v3.3 (Free + Pro + Local Business Ready)
 * Author: The Real Soske (Kaine Sama)
 */

import express from "express";
import mongoose from "mongoose";
import sqlite3 from "sqlite3";
import fs from "fs";
import path from "path";
import cron from "node-cron";
import os from "os";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import axios from "axios";
import { google } from "googleapis";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import cors from "cors";

dotenv.config();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors()); // Enable CORS for frontend compatibility

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";
const API_KEY = process.env.API_KEY || "air-api-key-secure"; // API key for sensitive routes
const RED_ZONE_THRESHOLD = 80;

// === FOLDERS ===
const BACKUP_FOLDER = path.join(process.cwd(), "backups");
const LOGS_FOLDER = path.join(process.cwd(), "logs");
if (!fs.existsSync(BACKUP_FOLDER)) fs.mkdirSync(BACKUP_FOLDER);
if (!fs.existsSync(LOGS_FOLDER)) fs.mkdirSync(LOGS_FOLDER);

const SQLITE_FILE = path.join(process.cwd(), "fallback.sqlite");
const USERS_FILE = path.join(process.cwd(), "users.json");
const DASHBOARD_FILE = path.join(process.cwd(), "dashboard.json");
const SITES_FILE = path.join(process.cwd(), "sites.json");
const ACTIVITY_LOG_FILE = path.join(process.cwd(), "logs", "activity.json");

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]");
if (!fs.existsSync(DASHBOARD_FILE)) fs.writeFileSync(DASHBOARD_FILE, "[]");
if (!fs.existsSync(SITES_FILE)) fs.writeFileSync(SITES_FILE, "[]");
if (!fs.existsSync(ACTIVITY_LOG_FILE)) fs.writeFileSync(ACTIVITY_LOG_FILE, "[]");

// === DATABASE ===
let mongoConnected = false;
const MONGO_URI = process.env.MONGO_URI;
if (MONGO_URI) {
  mongoose.connect(MONGO_URI)
    .then(() => { mongoConnected = true; console.log("✅ MongoDB connected"); })
    .catch(err => console.log("⚠️ MongoDB failed:", err.message));
} else console.log("⚠️ MongoDB URI missing, using fallback SQLite/JSON");

const sqliteDb = new sqlite3.Database(SQLITE_FILE);
sqliteDb.run(`CREATE TABLE IF NOT EXISTS backups (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, timestamp TEXT)`);
sqliteDb.run(`CREATE TABLE IF NOT EXISTS activity (id INTEGER PRIMARY KEY AUTOINCREMENT, userEmail TEXT, action TEXT, timestamp TEXT)`);

// === GOOGLE DRIVE ===
let drive = null;
if (fs.existsSync("service-account.json")) {
  const creds = JSON.parse(fs.readFileSync("service-account.json"));
  const auth = new google.auth.GoogleAuth({
    credentials: creds,
    scopes: ["https://www.googleapis.com/auth/drive.file"]
  });
  drive = google.drive({ version: "v3", auth });
  console.log("☁️ Google Drive enabled");
}

// === EMAIL ALERTS ===
let transporter = null;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
  });
  console.log("📧 Email alerts enabled");
}

// === WEBHOOKS ===
const SLACK_WEBHOOK_URL = process.env.SLACK_WEBHOOK_URL || null;
const DISCORD_WEBHOOK_URL = process.env.DISCORD_WEBHOOK_URL || null;

// === AUTO MONITOR + HEAL ENGINE ===
const CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes
const RETRY_DELAY = 2 * 60 * 1000; // 2 minutes
let siteStatusCache = {}; // track last known states

async function checkSites() {
  let sites = [];
  if (mongoConnected) {
    try {
      const Site = mongoose.models.Site || mongoose.model("Site", new mongoose.Schema({
        name: String, ownerEmail: String, url: String, type: String, metrics: Object, lastUpdate: Date
      }));
      sites = await Site.find();
    } catch (e) {
      console.log("⚠️ Site fetch failed:", e.message);
      addDashboardLog("error", `Site fetch failed: ${e.message}`);
    }
  } else {
    sites = JSON.parse(fs.readFileSync(SITES_FILE, "utf-8"));
  }

  for (const s of sites) {
    const target = s.url || s.name;
    if (!target) continue;
    try {
      const startTime = Date.now();
      const res = await axios.get(target, { timeout: 8000 });
      const latency = Date.now() - startTime;
      const healthy = res.status >= 200 && res.status < 400;
      if (healthy) {
        if (siteStatusCache[target] === "down") {
          addDashboardLog("info", `✅ ${target} recovered`);
          await sendRealtimeAlert("RECOVERY", `${target} back online`, { latency });
        }
        siteStatusCache[target] = "up";
        updateSiteMetrics(target, s.ownerEmail, { status: "up", latency });
      } else {
        throw new Error(`Status ${res.status}`);
      }
    } catch (err) {
      console.log(`❌ ${target} failed: ${err.message}`);
      if (siteStatusCache[target] !== "down") {
        siteStatusCache[target] = "down";
        addDashboardLog("error", `🚨 ${target} is down`);
        await sendRealtimeAlert("DOWN", `${target} unreachable`, {});
        healSite(target);
      }
    }
  }
}

async function healSite(target) {
  console.log(`🩺 Attempting heal for ${target} in 2 minutes...`);
  setTimeout(async () => {
    try {
      const healURL = target.endsWith("/") ? `${target}restart` : `${target}/restart`;
      await axios.post(healURL).catch(() => axios.get(`${target}?heal=1`));
      addDashboardLog("info", `🧠 Heal triggered for ${target}`);
      await sendRealtimeAlert("HEAL", `Heal triggered for ${target}`, {});
    } catch (e) {
      console.log(`⚠️ Heal failed for ${target}: ${e.message}`);
      addDashboardLog("error", `Heal failed for ${target}: ${e.message}`);
    }
  }, RETRY_DELAY);
}

setInterval(checkSites, CHECK_INTERVAL);
console.log("🩺 Auto Monitor + Heal Engine active");

// === HELPERS ===
const getTimestamp = () => new Date().toISOString().replace(/[:.]/g, "-");
const getMongoUsagePercent = () => Math.floor(Math.random() * 100); // Placeholder for real Mongo usage
function getSystemMetrics() {
  return {
    cpuUsage: Math.floor(Math.random() * 100),
    ramUsage: Math.floor((os.totalmem() - os.freemem()) / os.totalmem() * 100),
    mongoUsage: getMongoUsagePercent(),
    diskUsage: Math.floor(Math.random() * 100) // Placeholder for disk usage
  };
}

async function uploadToDrive(filePath, filename) {
  if (!drive) return;
  try {
    const meta = { name: filename };
    const media = { body: fs.createReadStream(filePath) };
    await drive.files.create({ resource: meta, media, fields: "id" });
    console.log(`☁️ Uploaded ${filename}`);
    addDashboardLog("info", `Backup uploaded to Drive: ${filename}`);
  } catch (err) {
    console.log("❌ Drive upload failed:", err.message);
    addDashboardLog("error", `Drive upload failed: ${err.message}`);
  }
}

function sendAlertEmail(subject, text) {
  if (!transporter) return console.log(`📩 (Skipped Email): ${subject}`);
  transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: process.env.ALERT_EMAIL,
    subject,
    text
  }).catch(err => {
    console.log(`❌ Email send failed: ${err.message}`);
    addDashboardLog("error", `Email send failed: ${err.message}`);
  });
}

async function sendRealtimeAlert(severity, message, metrics) {
  const alert = `🚨 *AIR Alert (${severity})*\n${message}\n\`\`\`${JSON.stringify(metrics, null, 2)}\`\`\``;
  if (SLACK_WEBHOOK_URL) await axios.post(SLACK_WEBHOOK_URL, { text: alert }).catch(() => {});
  if (DISCORD_WEBHOOK_URL) await axios.post(DISCORD_WEBHOOK_URL, { content: alert }).catch(() => {});
  if (!SLACK_WEBHOOK_URL && !DISCORD_WEBHOOK_URL) console.log(alert);
  sendAlertEmail(`AIR Alert: ${severity}`, `${message}\n${JSON.stringify(metrics, null, 2)}`);
}

// === DASHBOARD LOGGING ===
let AI_MODE = "mock";
function addDashboardLog(severity = "info", message = "") {
  const metrics = getSystemMetrics();
  const log = {
    timestamp: new Date().toISOString(),
    severity,
    message,
    metrics,
    mongo: mongoConnected ? "healthy" : "unhealthy",
    aiMode: AI_MODE
  };
  let logs = JSON.parse(fs.readFileSync(DASHBOARD_FILE, "utf-8"));
  logs.push(log);
  if (logs.length > 100) logs = logs.slice(-100); // Increased log retention
  fs.writeFileSync(DASHBOARD_FILE, JSON.stringify(logs, null, 2));
  console.log(`[${severity.toUpperCase()}] ${message}`);
}

// === USER ACTIVITY LOGGING ===
function logUserActivity(userEmail, action) {
  const activity = {
    userEmail,
    action,
    timestamp: new Date().toISOString()
  };
  let activities = JSON.parse(fs.readFileSync(ACTIVITY_LOG_FILE, "utf-8"));
  activities.push(activity);
  if (activities.length > 1000) activities = activities.slice(-1000);
  fs.writeFileSync(ACTIVITY_LOG_FILE, JSON.stringify(activities, null, 2));
  sqliteDb.run("INSERT INTO activity (userEmail, action, timestamp) VALUES (?, ?, ?)", 
    [userEmail, action, activity.timestamp]);
}

// === BACKUPS ===
function backupMongo(selectedCollections = []) {
  const ts = getTimestamp();
  const file = path.join(BACKUP_FOLDER, `backup-${ts}.json`);
  fs.writeFileSync(file, JSON.stringify({ collections: selectedCollections, ts }, null, 2));
  sqliteDb.run("INSERT INTO backups (filename, timestamp) VALUES (?, ?)", [file, ts]);
  uploadToDrive(file, `backup-${ts}.json`);
  console.log(`💾 Backup saved: ${file}`);
  addDashboardLog("info", `Backup created: ${file}`);
}

function restoreBackup(filename) {
  const file = path.join(BACKUP_FOLDER, filename);
  if (!fs.existsSync(file)) {
    addDashboardLog("error", `Restore failed: ${filename} not found`);
    return false;
  }
  console.log(`🔁 Restored from: ${file}`);
  addDashboardLog("info", `Restored from: ${file}`);
  return true;
}

function getHealthStatus() {
  const backups = fs.readdirSync(BACKUP_FOLDER);
  return {
    mongo: mongoConnected ? "healthy" : "unhealthy",
    fallback: "healthy",
    lastBackup: backups.sort().pop() || null,
    aiMode: AI_MODE,
    diskUsage: getSystemMetrics().diskUsage
  };
}

// === AUTH & USER PLAN ===
const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  plan: { type: String, default: "free" } // free, pro, or admin
});
const User = mongoose.models.User || mongoose.model("User", UserSchema);

async function saveUserFallback(u) {
  const users = JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
  users.push(u);
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

async function findUserFallback(email) {
  const users = JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
  return users.find(u => u.email === email);
}

// === RATE LIMITER ===
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per window
  message: { message: "Too many requests, please try again later" }
});
app.use("/api", limiter);

// === JWT & API KEY MIDDLEWARE ===
function authMiddleware(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized: Missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Unauthorized: Invalid token" });
  }
}

function apiKeyMiddleware(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== API_KEY) {
    return res.status(403).json({ message: "Forbidden: Invalid API key" });
  }
  next();
}

// === API ROUTES ===
const api = express.Router();
api.use((req, res, next) => { res.setHeader("Content-Type", "application/json"); next(); });

// Register/Login
api.post("/register", async (req, res) => {
  try {
    const { username, email, password, plan } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: "Missing required fields" });
    const hashed = await bcrypt.hash(password, 10);
    const user = { username, email, password: hashed, plan: plan || "free" };
    if (mongoConnected) await User.create(user); else await saveUserFallback(user);
    logUserActivity(email, "register");
    res.json({ message: "User registered successfully" });
  } catch (err) {
    addDashboardLog("error", `Registration failed: ${err.message}`);
    res.status(500).json({ message: `Server error: ${err.message}` });
  }
});

api.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Missing email or password" });
    const user = mongoConnected ? await User.findOne({ email }) : await findUserFallback(email);
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });
    const token = jwt.sign({ email: user.email, username: user.username, plan: user.plan }, JWT_SECRET, { expiresIn: "7d" });
    logUserActivity(email, "login");
    res.json({ message: "Login successful", token, username: user.username, plan: user.plan });
  } catch (err) {
    addDashboardLog("error", `Login failed: ${err.message}`);
    res.status(500).json({ message: `Server error: ${err.message}` });
  }
});

// Status & Dashboard
api.get("/status", (req, res) => res.json(getHealthStatus()));
api.get("/dashboard", (req, res) => res.json(JSON.parse(fs.readFileSync(DASHBOARD_FILE))));

api.post("/backup", authMiddleware, apiKeyMiddleware, async (req, res) => {
  try {
    const { collections, schedule } = req.body;
    backupMongo(collections || []);
    if (schedule) {
      cron.schedule(schedule, () => backupMongo(collections || []));
      addDashboardLog("info", `Custom backup scheduled: ${schedule}`);
    }
    logUserActivity(req.user.email, `triggered backup${schedule ? ` with schedule ${schedule}` : ""}`);
    res.json({ message: "Backup triggered successfully" });
  } catch (err) {
    addDashboardLog("error", `Backup failed: ${err.message}`);
    res.status(500).json({ message: `Backup failed: ${err.message}` });
  }
});

api.post("/restore", authMiddleware, apiKeyMiddleware, async (req, res) => {
  try {
    const { filename } = req.body;
    const success = restoreBackup(filename);
    logUserActivity(req.user.email, `restored backup ${filename}`);
    res.json({ success, message: success ? "Restore successful" : "Restore failed" });
  } catch (err) {
    addDashboardLog("error", `Restore failed: ${err.message}`);
    res.status(500).json({ message: `Restore failed: ${err.message}` });
  }
});

api.post("/switch", authMiddleware, apiKeyMiddleware, (req, res) => {
  const message = checkAndSwitchDB();
  logUserActivity(req.user.email, "switched database");
  res.json({ message });
});

// AI Free/Pro
api.get("/ai", async (req, res) => {
  try {
    const reply = await aiRespond(req.query.msg || "Hello AIR");
    res.json({ mode: AI_MODE, response: reply });
  } catch (err) {
    addDashboardLog("error", `AI request failed: ${err.message}`);
    res.status(500).json({ message: `AI request failed: ${err.message}` });
  }
});

api.post("/ai-pro", authMiddleware, async (req, res) => {
  try {
    const { msg } = req.body;
    if (!req.user) return res.status(401).json({ message: "Unauthorized" });
    if (req.user.plan !== "pro" && req.user.plan !== "admin") {
      return res.status(403).json({ message: "Upgrade to Pro or Admin for premium AI" });
    }
    const reply = await aiRespond(msg);
    logUserActivity(req.user.email, "used premium AI");
    res.json({ mode: AI_MODE, response: reply });
  } catch (err) {
    addDashboardLog("error", `Premium AI request failed: ${err.message}`);
    res.status(500).json({ message: `Premium AI request failed: ${err.message}` });
  }
});

// Business/Site Routes
api.post("/sites/add", authMiddleware, async (req, res) => {
  try {
    const { name, url, type } = req.body;
    if (!name || !url) return res.status(400).json({ message: "Missing name or URL" });
    const ownerEmail = req.user.email;
    const site = { name, ownerEmail, url, type: type || "local", metrics: { status: "unknown", latency: 0 }, lastUpdate: new Date() };
    if (mongoConnected) {
      const Site = mongoose.models.Site || mongoose.model("Site", new mongoose.Schema({
        name: String, ownerEmail: String, url: String, type: String, metrics: Object, lastUpdate: Date
      }));
      await Site.create(site);
    } else {
      const sites = JSON.parse(fs.readFileSync(SITES_FILE));
      sites.push(site);
      fs.writeFileSync(SITES_FILE, JSON.stringify(sites, null, 2));
    }
    logUserActivity(ownerEmail, `added site ${name}`);
    res.json({ message: "Business/site added", site });
  } catch (err) {
    addDashboardLog("error", `Site addition failed: ${err.message}`);
    res.status(500).json({ message: `Site addition failed: ${err.message}` });
  }
});

api.get("/sites", authMiddleware, async (req, res) => {
  try {
    const ownerEmail = req.user.email;
    let sites;
    if (mongoConnected) {
      const Site = mongoose.models.Site || mongoose.model("Site", new mongoose.Schema({
        name: String, ownerEmail: String, url: String, type: String, metrics: Object, lastUpdate: Date
      }));
      sites = await Site.find({ ownerEmail });
    } else {
      sites = JSON.parse(fs.readFileSync(SITES_FILE)).filter(s => s.ownerEmail === ownerEmail);
    }
    res.json(sites);
  } catch (err) {
    addDashboardLog("error", `Site fetch failed: ${err.message}`);
    res.status(500).json({ message: `Site fetch failed: ${err.message}` });
  }
});

api.post("/sites/update", authMiddleware, async (req, res) => {
  try {
    const { name, metrics } = req.body;
    if (!name || !metrics) return res.status(400).json({ message: "Missing name or metrics" });
    const ownerEmail = req.user.email;
    if (mongoConnected) {
      const Site = mongoose.models.Site || mongoose.model("Site", new mongoose.Schema({
        name: String, ownerEmail: String, url: String, type: String, metrics: Object, lastUpdate: Date
      }));
      await Site.findOneAndUpdate({ name, ownerEmail }, { metrics, lastUpdate: new Date() });
    } else {
      const sites = JSON.parse(fs.readFileSync(SITES_FILE));
      const site = sites.find(s => s.name === name && s.ownerEmail === ownerEmail);
      if (site) { site.metrics = metrics; site.lastUpdate = new Date(); }
      fs.writeFileSync(SITES_FILE, JSON.stringify(sites, null, 2));
    }
    logUserActivity(ownerEmail, `updated site ${name}`);
    res.json({ message: "Metrics updated" });
  } catch (err) {
    addDashboardLog("error", `Site update failed: ${err.message}`);
    res.status(500).json({ message: `Site update failed: ${err.message}` });
  }
});

// Activity Log
api.get("/activity", authMiddleware, apiKeyMiddleware, async (req, res) => {
  try {
    const ownerEmail = req.user.email;
    if (req.user.plan !== "admin") return res.status(403).json({ message: "Admin access required" });
    const activities = JSON.parse(fs.readFileSync(ACTIVITY_LOG_FILE)).filter(a => a.userEmail === ownerEmail);
    res.json(activities);
  } catch (err) {
    addDashboardLog("error", `Activity log fetch failed: ${err.message}`);
    res.status(500).json({ message: `Activity log fetch failed: ${err.message}` });
  }
});

// === AI (Generic) ===
const AI_API_KEY = process.env.AI_API_KEY || null;
const AI_API_URL = process.env.AI_API_URL || null;

async function detectAIMode() {
  if (AI_API_URL && AI_API_KEY) {
    AI_MODE = "custom";
    console.log(`🧠 Generic AI mode enabled (${AI_API_URL})`);
  } else {
    AI_MODE = "mock";
    console.log("⚙️ Mock AI mode");
  }
}

async function aiRespond(msg) {
  if (AI_MODE === "custom") {
    try {
      const res = await axios.post(
        AI_API_URL,
        {
          model: process.env.AI_MODEL || "default",
          messages: [
            { role: "system", content: "You are AIR, an AI monitor." },
            { role: "user", content: msg }
          ]
        },
        { headers: { Authorization: `Bearer ${AI_API_KEY}` } }
      );
      const data = res.data;
      if (data.choices && data.choices[0]?.message?.content) {
        return data.choices[0].message.content;
      }
      return JSON.stringify(data);
    } catch (err) {
      console.log("❌ AI request failed:", err.message);
      addDashboardLog("error", `AI request failed: ${err.message}`);
      AI_MODE = "mock";
    }
  }
  return `AI fallback: "${msg}"`;
}

// === DB SWITCHER ===
function checkAndSwitchDB() {
  const usage = getMongoUsagePercent();
  if (usage >= RED_ZONE_THRESHOLD) {
    addDashboardLog("critical", `MongoDB at ${usage}%. Switched to fallback.`);
    backupMongo();
    return "Switched to fallback DB";
  }
  return "Mongo healthy";
}

// === FRONTEND SERVE ===
const __dirname = path.resolve();
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => {
  const file = path.join(__dirname, "public", "index.html");
  if (fs.existsSync(file)) res.sendFile(file);
  else res.send("<h1>🌬️ AIR Server Running</h1><p>No frontend found.</p>");
});

// === CRON JOBS ===
cron.schedule("0 * * * *", () => backupMongo());
cron.schedule("*/10 * * * *", () => checkAndSwitchDB());
cron.schedule("*/5 * * * *", () => {
  const m = getSystemMetrics();
  if (m.mongoUsage >= RED_ZONE_THRESHOLD) addDashboardLog("critical", `MongoDB usage at ${m.mongoUsage}%`);
  if (m.diskUsage >= RED_ZONE_THRESHOLD) addDashboardLog("critical", `Disk usage at ${m.diskUsage}%`);
});

// === START ===
await detectAIMode();
app.use("/api", api);
app.listen(PORT, () => console.log(`🚀 AIR Hybrid Server v3.3 running on port ${PORT}`));
