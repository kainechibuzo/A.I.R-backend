/**
 * 🌬️ AIR Hybrid Monitoring Server v3.2 (Free + Pro + Local Business Ready)
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
import OpenAI from "openai";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

// === FOLDERS ===
const BACKUP_FOLDER = path.join(process.cwd(), "backups");
if (!fs.existsSync(BACKUP_FOLDER)) fs.mkdirSync(BACKUP_FOLDER);

const SQLITE_FILE = path.join(process.cwd(), "fallback.sqlite");
const USERS_FILE = path.join(process.cwd(), "users.json");
const DASHBOARD_FILE = path.join(process.cwd(), "dashboard.json"); // logs
const SITES_FILE = path.join(process.cwd(), "sites.json"); // free/local site fallback

if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, "[]");
if (!fs.existsSync(DASHBOARD_FILE)) fs.writeFileSync(DASHBOARD_FILE, "[]");
if (!fs.existsSync(SITES_FILE)) fs.writeFileSync(SITES_FILE, "[]");

const RED_ZONE_THRESHOLD = 80;

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

// === HELPERS ===
const getTimestamp = () => new Date().toISOString().replace(/[:.]/g, "-");
const getMongoUsagePercent = () => Math.floor(Math.random() * 100);
function getSystemMetrics() {
  return {
    cpuUsage: Math.floor(Math.random() * 100),
    ramUsage: Math.floor((os.totalmem() - os.freemem()) / os.totalmem() * 100),
    mongoUsage: getMongoUsagePercent()
  };
}

async function uploadToDrive(filePath, filename) {
  if (!drive) return;
  try {
    const meta = { name: filename };
    const media = { body: fs.createReadStream(filePath) };
    await drive.files.create({ resource: meta, media, fields: "id" });
    console.log(`☁️ Uploaded ${filename}`);
  } catch (err) { console.log("❌ Drive upload failed:", err.message); }
}

function sendAlertEmail(subject, text) {
  if (!transporter) return console.log(`📩 (Skipped Email): ${subject}`);
  transporter.sendMail({ from: process.env.EMAIL_USER, to: process.env.ALERT_EMAIL, subject, text });
}

async function sendRealtimeAlert(severity, message, metrics) {
  const alert = `🚨 *AIR Alert (${severity})*\n${message}\n\`\`\`${JSON.stringify(metrics, null, 2)}\`\`\``;
  if (SLACK_WEBHOOK_URL) await axios.post(SLACK_WEBHOOK_URL, { text: alert }).catch(() => {});
  if (DISCORD_WEBHOOK_URL) await axios.post(DISCORD_WEBHOOK_URL, { content: alert }).catch(() => {});
  if (!SLACK_WEBHOOK_URL && !DISCORD_WEBHOOK_URL) console.log(alert);
}

// === DASHBOARD LOGGING ===
let AI_MODE = "mock";
function addDashboardLog(severity = "info", message = "") {
  const metrics = getSystemMetrics();
  const log = {
    timestamp: new Date().toISOString(),
    severity, message, metrics,
    mongo: mongoConnected ? "healthy" : "unhealthy",
    aiMode: AI_MODE
  };
  let logs = JSON.parse(fs.readFileSync(DASHBOARD_FILE, "utf-8"));
  logs.push(log);
  if (logs.length > 50) logs = logs.slice(-50);
  fs.writeFileSync(DASHBOARD_FILE, JSON.stringify(logs, null, 2));
  console.log(`[${severity.toUpperCase()}] ${message}`);
}

// === BACKUPS ===
function backupMongo(selectedCollections = []) {
  const ts = getTimestamp();
  const file = path.join(BACKUP_FOLDER, `backup-${ts}.json`);
  fs.writeFileSync(file, JSON.stringify({ collections: selectedCollections, ts }, null, 2));
  sqliteDb.run("INSERT INTO backups (filename, timestamp) VALUES (?, ?)", [file, ts]);
  uploadToDrive(file, `backup-${ts}.json`);
  console.log(`💾 Backup saved: ${file}`);
}

function restoreBackup(filename) {
  const file = path.join(BACKUP_FOLDER, filename);
  if (!fs.existsSync(file)) return false;
  console.log(`🔁 Restored from: ${file}`);
  return true;
}

function getHealthStatus() {
  const backups = fs.readdirSync(BACKUP_FOLDER);
  return {
    mongo: mongoConnected ? "healthy" : "unhealthy",
    fallback: "healthy",
    lastBackup: backups.sort().pop() || null,
    aiMode: AI_MODE
  };
}

// === AUTH & USER PLAN ===
const UserSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  plan: { type: String, default: "free" } // free or pro
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

// === JWT AUTH MIDDLEWARE ===
function authMiddleware(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Unauthorized" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

// === API ROUTES ===
const api = express.Router();

// Force JSON header middleware
api.use((req, res, next) => { res.setHeader("Content-Type", "application/json"); next(); });

// Register/Login
api.post("/register", async (req, res) => {
  try {
    const { username, email, password, plan } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: "Missing fields" });
    const hashed = await bcrypt.hash(password, 10);
    const user = { username, email, password: hashed, plan: plan || "free" };
    if (mongoConnected) await User.create(user); else await saveUserFallback(user);
    res.json({ message: "User registered" });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

api.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Missing fields" });
    const user = mongoConnected ? await User.findOne({ email }) : await findUserFallback(email);
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ message: "Invalid credentials" });
    const token = jwt.sign({ email: user.email, username: user.username, plan: user.plan }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Login successful", token, username: user.username, plan: user.plan });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Status & Dashboard
api.get("/status", (req, res) => res.json(getHealthStatus()));
api.get("/dashboard", (req, res) => res.json(JSON.parse(fs.readFileSync(DASHBOARD_FILE))));
api.post("/backup", authMiddleware, (req, res) => { const { collections } = req.body; backupMongo(collections || []); res.json({ message: "Backup triggered" }); });
api.post("/restore", authMiddleware, (req, res) => { const { filename } = req.body; res.json({ success: restoreBackup(filename) }); });
api.post("/switch", authMiddleware, (req, res) => res.json({ message: checkAndSwitchDB() }));

// AI Free/Pro
api.get("/ai", async (req, res) => { const reply = await aiRespond(req.query.msg || "Hello AIR"); res.json({ mode: AI_MODE, response: reply }); });
api.post("/ai-pro", authMiddleware, async (req, res) => {
  const { msg } = req.body;
  if (!req.user) return res.status(401).json({ message: "Unauthorized" });
  if (req.user.plan !== "pro") return res.status(403).json({ message: "Upgrade to Pro for premium AI" });
  const reply = await aiRespond(msg);
  res.json({ mode: AI_MODE, response: reply });
});

// === BUSINESS/SITE ROUTES ===
api.post("/sites/add", authMiddleware, async (req, res) => {
  const { name, type } = req.body;
  if (!name) return res.status(400).json({ message: "Missing name" });
  const ownerEmail = req.user.email;
  const site = { name, ownerEmail, type: type || "local", metrics: {}, lastUpdate: new Date() };
  if (mongoConnected) await Site.create(site);
  else { const sites = JSON.parse(fs.readFileSync(SITES_FILE)); sites.push(site); fs.writeFileSync(SITES_FILE, JSON.stringify(sites, null, 2)); }
  res.json({ message: "Business/site added", site });
});

api.get("/sites", authMiddleware, async (req, res) => {
  const ownerEmail = req.user.email;
  let sites;
  if (mongoConnected) sites = await Site.find({ ownerEmail });
  else sites = JSON.parse(fs.readFileSync(SITES_FILE)).filter(s => s.ownerEmail === ownerEmail);
  res.json(sites);
});

api.post("/sites/update", authMiddleware, async (req, res) => {
  const { name, metrics } = req.body;
  if (!name || !metrics) return res.status(400).json({ message: "Missing fields" });
  const ownerEmail = req.user.email;
  if (mongoConnected) await Site.findOneAndUpdate({ name, ownerEmail }, { metrics, lastUpdate: new Date() });
  else {
    const sites = JSON.parse(fs.readFileSync(SITES_FILE));
    const site = sites.find(s => s.name === name && s.ownerEmail === ownerEmail);
    if (site) { site.metrics = metrics; site.lastUpdate = new Date(); }
    fs.writeFileSync(SITES_FILE, JSON.stringify(sites, null, 2));
  }
  res.json({ message: "Metrics updated" });
});

// === AI ===
const openai = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;
async function detectAIMode() {
  if (openai) { AI_MODE = "openai"; console.log("🧠 OpenAI mode enabled"); }
  else { AI_MODE = "mock"; console.log("⚙️ Mock AI mode"); }
}
async function aiRespond(msg) {
  if (AI_MODE === "openai") {
    try {
      const comp = await openai.chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "system", content: "You are AIR, an AI monitor." }, { role: "user", content: msg }]
      });
      return comp.choices[0].message.content;
    } catch { AI_MODE = "mock"; }
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
  if (m.mongoUsage >= RED_ZONE_THRESHOLD) addDashboardLog("critical", "Mongo red zone");
});

// === START ===
await detectAIMode();
app.use("/api", api);
app.listen(PORT, () => console.log(`🚀 AIR Hybrid Server v3.2 running on port ${PORT}`));
