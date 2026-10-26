import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import Database from "better-sqlite3";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = Number(process.env.PORT || 3000);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 16) {
  console.error("Set ADMIN_PASSWORD to a long random value (at least 16 characters).");
  process.exit(1);
}

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "10kb" }));
app.use("/api/", rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: "draft-7", legacyHeaders: false }));
app.use(express.static(path.join(__dirname, "public")));

const db = new Database(process.env.DB_PATH || path.join(__dirname, "phantom.sqlite"));
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS access_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
  )
`);
const hashKey = key => crypto.createHash("sha256").update(key).digest("hex");
const safeEqual = (a, b) => {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};
function requireAdmin(req, res, next) {
  const auth = req.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!token || !safeEqual(token, ADMIN_PASSWORD)) return res.status(401).json({ ok: false, message: "Unauthorized" });
  next();
}
app.post("/api/validate", (req, res) => {
  const key = typeof req.body?.key === "string" ? req.body.key.trim() : "";
  if (!key || key.length > 160) return res.status(400).json({ ok: false, message: "Enter a valid key format." });
  const row = db.prepare("SELECT expires_at, revoked FROM access_keys WHERE key_hash = ?").get(hashKey(key));
  if (!row) return res.status(200).json({ ok: false, message: "Key not found." });
  if (row.revoked) return res.status(200).json({ ok: false, message: "This key has been revoked." });
  if (Date.parse(row.expires_at) <= Date.now()) return res.status(200).json({ ok: false, message: "This key has expired." });
  return res.json({ ok: true, message: "Access granted.", expiresAt: row.expires_at });
});
app.get("/api/admin/keys", requireAdmin, (req, res) => {
  const rows = db.prepare("SELECT id, label, created_at AS createdAt, expires_at AS expiresAt, revoked FROM access_keys ORDER BY id DESC LIMIT 200").all();
  res.json({ ok: true, keys: rows });
});
app.post("/api/admin/keys", requireAdmin, (req, res) => {
  const days = Number(req.body?.days);
  const label = typeof req.body?.label === "string" ? req.body.label.trim().slice(0, 80) : "";
  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    return res.status(400).json({ ok: false, message: "Expiry must be from 1 to 3650 days." });
  }
  const rawKey = "PH-" + crypto.randomBytes(18).toString("base64url").toUpperCase();
  const now = new Date();
  const expires = new Date(now.getTime() + days * 86400000);
  db.prepare("INSERT INTO access_keys (key_hash, label, created_at, expires_at) VALUES (?, ?, ?, ?)")
    .run(hashKey(rawKey), label, now.toISOString(), expires.toISOString());
  // The full key is shown only once; only its SHA-256 hash is stored.
  res.status(201).json({ ok: true, key: rawKey, expiresAt: expires.toISOString() });
});
app.post("/api/admin/keys/:id/revoke", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ ok: false, message: "Invalid key ID." });
  const result = db.prepare("UPDATE access_keys SET revoked = 1 WHERE id = ?").run(id);
  if (!result.changes) return res.status(404).json({ ok: false, message: "Key not found." });
  res.json({ ok: true, message: "Key revoked." });
});
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) return res.status(404).json({ ok: false, message: "Not found" });
  res.sendFile(path.join(__dirname, "public", "index.html"), err => { if (err) next(err); });
});
app.listen(PORT, () => console.log(`PHANTOM access system running on http://localhost:${PORT}`));
