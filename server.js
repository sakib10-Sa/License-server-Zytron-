const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

// ---------------- Config & DB -----------------
const DB_PATH = path.join(__dirname, "keys.json");
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "change-me-to-a-long-random-string";
const APP_PACKAGE_NAME = process.env.APP_PACKAGE_NAME || "com.yourcompany.cloudpro";
let MIN_SUPPORTED_VERSION = process.env.MIN_SUPPORTED_VERSION || "1.0.0";

function loadDB() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ keys: {}, commands: [] }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}
function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}
function generateKey() {
  const raw = crypto.randomBytes(8).toString("hex").toUpperCase();
  return raw.match(/.{1,4}/g).join("-");
}
function versionAtLeast(version, minVersion) {
  const a = version.split(".").map(Number);
  const b = minVersion.split(".").map(Number);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i] || 0;
    const y = b[i] || 0;
    if (x > y) return true;
    if (x < y) return false;
  }
  return true;
}
function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (!token || token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

// ------------ API Routes ------------
app.post("/api/validate", (req, res) => {
  const { key, device_id, app_version, package_name } = req.body || {};
  if (!key || !device_id) {
    return res.status(400).json({ valid: false, reason: "missing_fields" });
  }
  if (package_name && package_name !== APP_PACKAGE_NAME) {
    return res.status(200).json({ valid: false, reason: "wrong_package" });
  }
  if (app_version && !versionAtLeast(app_version, MIN_SUPPORTED_VERSION)) {
    return res.status(200).json({ valid: false, reason: "update_required", min_version: MIN_SUPPORTED_VERSION });
  }
  const db = loadDB();
  const record = db.keys[key];
  if (!record) return res.status(200).json({ valid: false, reason: "unknown_key" });
  if (record.revoked) return res.status(200).json({ valid: false, reason: "revoked" });
  if (record.expires_at && Date.now() > record.expires_at) {
    return res.status(200).json({ valid: false, reason: "expired" });
  }
  if (record.locked_device_id && record.locked_device_id !== device_id) {
    return res.status(200).json({ valid: false, reason: "device_mismatch" });
  }
  if (!record.locked_device_id) {
    record.locked_device_id = device_id;
    record.activated_at = record.activated_at || Date.now();
  }
  record.last_seen = Date.now();
  record.last_seen_device_id = device_id;
  saveDB(db);
  return res.status(200).json({ valid: true, plan: record.plan || "pro", expires_at: record.expires_at || null });
});

app.post("/api/admin/keys", requireAdmin, (req, res) => {
  const { plan, expires_in_days, note } = req.body || {};
  const db = loadDB();
  const key = generateKey();
  db.keys[key] = {
    plan: plan || "pro",
    note: note || "",
    created_at: Date.now(),
    expires_at: expires_in_days ? Date.now() + expires_in_days * 24 * 60 * 60 * 1000 : null,
    revoked: false,
    locked_device_id: null,
  };
  saveDB(db);
  res.status(201).json({ key, ...db.keys[key] });
});

app.get("/api/admin/keys", requireAdmin, (req, res) => {
  const db = loadDB();
  res.json(db.keys);
});

app.patch("/api/admin/keys/:key", requireAdmin, (req, res) => {
  const db = loadDB();
  const record = db.keys[req.params.key];
  if (!record) return res.status(404).json({ error: "not_found" });
  const { revoked, plan, expires_at, unlock_device } = req.body || {};
  if (typeof revoked === "boolean") record.revoked = revoked;
  if (plan) record.plan = plan;
  if (expires_at !== undefined) record.expires_at = expires_at;
  if (unlock_device) record.locked_device_id = null;
  saveDB(db);
  res.json({ key: req.params.key, ...record });
});

app.delete("/api/admin/keys/:key", requireAdmin, (req, res) => {
  const db = loadDB();
  delete db.keys[req.params.key];
  saveDB(db);
  res.status(204).send();
});

app.post("/api/admin/config", requireAdmin, (req, res) => {
  const { min_supported_version } = req.body || {};
  if (min_supported_version) MIN_SUPPORTED_VERSION = min_supported_version;
  res.json({ min_supported_version: MIN_SUPPORTED_VERSION });
});

app.get("/health", (req, res) => res.json({ ok: true }));

// ------------ WebSocket & Commands ------------
function addCommand(targetDeviceId, payload) {
  const db = loadDB();
  db.commands = db.commands || [];
  db.commands.push({
    targetDeviceId: targetDeviceId || null,
    payload: JSON.stringify(payload),
    sentAt: Date.now(),
    delivered: false
  });
  saveDB(db);
}

function getPendingCommands(deviceId) {
  const db = loadDB();
  return (db.commands || []).filter(
    c => (c.targetDeviceId === deviceId || c.targetDeviceId === null) && !c.delivered
  );
}

function markCommandDelivered(cmdId) {
  const db = loadDB();
  const cmd = db.commands.find(c => c.id === cmdId);
  if (cmd) cmd.delivered = true;
  saveDB(db);
}

io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);

  socket.on("authenticate", ({ key, device_id }) => {
    const db = loadDB();
    const record = db.keys[key];
    if (!record || record.revoked || (record.locked_device_id && record.locked_device_id !== device_id)) {
      socket.emit("error", "Authentication failed");
      socket.disconnect();
      return;
    }
    socket.deviceId = device_id;
    socket.key = key;
    socket.join(`device-${device_id}`);

    const pending = getPendingCommands(device_id);
    pending.forEach(cmd => {
      socket.emit("command", JSON.parse(cmd.payload));
      markCommandDelivered(cmd.id);
    });
  });

  socket.on("admin-command", ({ targetDeviceId, payload }) => {
    addCommand(targetDeviceId || null, payload);
    if (targetDeviceId) {
      io.to(`device-${targetDeviceId}`).emit("command", payload);
    } else {
      io.emit("command", payload);
    }
  });

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`✅ License + Command server running on port ${PORT}`);
});
