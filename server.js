const express = require("express");
const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { exec } = require("child_process");

const { readJson, updateJson } = require("./lib/dataStore");
const { createAuth } = require("./lib/auth");
const { hashPassword, verifyPassword, issueToken, verifyToken } = require("./lib/security");
const { callNodeCommand, callNodeFiles, callNodeEndpoint } = require("./lib/wingsClient");
const { createWsHub } = require("./lib/wsHub");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const TOKEN_TTL_SECONDS = Number(process.env.JWT_TTL_SECONDS || 60 * 60 * 24);

const DEFAULT_PANEL_SETTINGS = {
  default_theme: "gray",
  button_color: "",
  sidebar_color: "",
  card_color: "",
  background_image: "",
  default_server_limit: 1,
};
const DEFAULT_THEMES = [
  {
    id: "gray",
    name: "Gray",
    locked: true,
    palette: {
      background: "#1a1f26",
      sidebar: "#151a21",
      card: "#1f252e",
      text: "#e6e9ef",
      muted: "#9aa3af",
      line: "#2a323d",
      input_bg: "#232a34",
      input_text: "#e6e9ef",
      table_head: "#222833",
      hover_bg: "rgba(255,255,255,0.04)",
      accent: "#4f8cff",
      button: "#2d3645",
    },
  },
  {
    id: "dark",
    name: "Dark",
    locked: true,
    palette: {
      background: "#12151b",
      sidebar: "#191d25",
      card: "#1d222c",
      text: "#eef1f7",
      muted: "#9aa4b2",
      line: "#2e3440",
      input_bg: "#202531",
      input_text: "#eef1f7",
      table_head: "#232937",
      hover_bg: "rgba(255,255,255,0.05)",
      accent: "#4f8cff",
      button: "#2d3645",
    },
  },
  {
    id: "light",
    name: "Light",
    locked: true,
    palette: {
      background: "#edf0f5",
      sidebar: "#e3e7ee",
      card: "#ffffff",
      text: "#1f2328",
      muted: "#5a616d",
      line: "#d6dbe3",
      input_bg: "#ffffff",
      input_text: "#1f2328",
      table_head: "#e9edf3",
      hover_bg: "rgba(0,0,0,0.04)",
      accent: "#4f8cff",
      button: "#3b3f45",
    },
  },
  {
    id: "hacker",
    name: "Hacker",
    locked: true,
    palette: {
      background: "#0a0f0c",
      sidebar: "#0f1713",
      card: "#101c16",
      text: "#d9ffe8",
      muted: "#7fc9a4",
      line: "#173425",
      input_bg: "#111d17",
      input_text: "#d9ffe8",
      table_head: "#122119",
      hover_bg: "rgba(120,255,180,0.08)",
      accent: "#25f4a0",
      button: "#1f7a52",
    },
  },
  {
    id: "pterodactyl",
    name: "Pterodactyl",
    locked: true,
    palette: {
      background: "#0f172a",
      sidebar: "#111827",
      card: "#111827",
      text: "#e5e7eb",
      muted: "#9ca3af",
      line: "#1f2937",
      input_bg: "#111827",
      input_text: "#e5e7eb",
      table_head: "#1f2937",
      hover_bg: "rgba(59,130,246,0.08)",
      accent: "#3b82f6",
      button: "#2563eb",
    },
  },
  {
    id: "pufferpanel",
    name: "PufferPanel",
    locked: true,
    palette: {
      background: "#141218",
      sidebar: "#1a1622",
      card: "#1b1824",
      text: "#f5f3ff",
      muted: "#b9b3c8",
      line: "#2b2437",
      input_bg: "#1c1a25",
      input_text: "#f5f3ff",
      table_head: "#221d2d",
      hover_bg: "rgba(255,159,67,0.1)",
      accent: "#f97316",
      button: "#f97316",
    },
  },
  {
    id: "ctrlpanel",
    name: "CtrlPanel.gg",
    locked: true,
    palette: {
      background: "#101417",
      sidebar: "#151a1f",
      card: "#171c22",
      text: "#e6f1ff",
      muted: "#98a2b3",
      line: "#242b33",
      input_bg: "#1a2028",
      input_text: "#e6f1ff",
      table_head: "#1f2630",
      hover_bg: "rgba(0,214,255,0.08)",
      accent: "#00d6ff",
      button: "#0ea5e9",
    },
  },
];

const DEFAULT_UPDATE_STATE = {
  source_url: "https://github.com/DragoraLabs/nodedash.github.io/releases/tag/version",
  remote_version: null,
  checked_at: null,
  update_available: false,
  last_error: null,
  last_update_at: null,
  last_update_log: null,
};

const DEFAULT_RUNTIME_VERSIONS = {
  node: ["18", "20", "22"],
  python: ["3.9", "3.10", "3.11", "3.12"],
  java: ["8", "11", "17", "21"],
};

const THEME_ID_PATTERN = /^[a-z0-9-]+$/;

const app = express();

const baseDir = __dirname;
const dataDir = path.join(baseDir, "data");
const publicDir = path.join(baseDir, "public");
const keysDir = path.join(dataDir, "keys");
const panelPrivateKeyPath = path.join(keysDir, "panel_rsa_private.pem");
const panelPublicKeyPath = path.join(keysDir, "panel_rsa_public.pem");

const usersFile = path.join(dataDir, "users.json");
const sessionsFile = path.join(dataDir, "sessions.json");
const nodesFile = path.join(dataDir, "nodes.json");
const serversFile = path.join(dataDir, "servers.json");
const logsFile = path.join(dataDir, "logs.json");
const panelSettingsFile = path.join(dataDir, "panel_settings.json");
const apiKeysFile = path.join(dataDir, "api_keys.json");
const themesFile = path.join(dataDir, "themes.json");
const updateStateFile = path.join(dataDir, "update_state.json");
const runtimeVersionsFile = path.join(dataDir, "runtime_versions.json");

const serverEvents = new Map();

const { attachUser, requireAdmin, sanitizeUser, getBearerToken } = createAuth(dataDir);

function nowIso() {
  return new Date().toISOString();
}

function ensurePanelKeys() {
  if (fs.existsSync(panelPrivateKeyPath) && fs.existsSync(panelPublicKeyPath)) {
    return;
  }
  fs.mkdirSync(keysDir, { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  fs.writeFileSync(panelPrivateKeyPath, privateKey);
  fs.writeFileSync(panelPublicKeyPath, publicKey);
}

function readPanelPrivateKey() {
  return fs.readFileSync(panelPrivateKeyPath, "utf8");
}

function readPanelPublicKey() {
  return fs.readFileSync(panelPublicKeyPath, "utf8");
}

const replaySet = new Set();
const replayQueue = [];
const REPLAY_LIMIT = 5000;

function canonical(method, pathName, ts, nonce, body) {
  return `${String(method).toUpperCase()}\n${pathName}\n${ts}\n${nonce}\n${JSON.stringify(body || {})}`;
}

function signHmac(payload, secret) {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

function verifyHmac(payload, secret, signature) {
  const expected = signHmac(payload, secret);
  const received = String(signature || "");
  if (received.length !== expected.length) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(received));
}

function signRsa(payload, privateKeyPem) {
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(payload);
  signer.end();
  return signer.sign(privateKeyPem, "base64");
}

function verifyRsa(payload, signature, publicKeyPem) {
  try {
    const verifier = crypto.createVerify("RSA-SHA256");
    verifier.update(payload);
    verifier.end();
    return verifier.verify(publicKeyPem, signature, "base64");
  } catch {
    return false;
  }
}

function isFresh(ts, ttlMs = 30000) {
  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return false;
  return Math.abs(Date.now() - tsNum) <= ttlMs;
}

async function verifySignedNodeRequest(req) {
  const nodeId = String(req.headers["x-node-id"] || "").trim();
  const tokenHeader = String(req.headers.authorization || "").replace("Bearer ", "").trim();
  const panelSecretHeader = String(req.headers["x-panel-secret"] || "").trim();
  const ts = String(req.headers["x-ts"] || "").trim();
  const nonce = String(req.headers["x-nonce"] || "").trim();
  const sig = String(req.headers["x-signature"] || "").trim();
  const rsaSig = String(req.headers["x-rsa-signature"] || "").trim();

  if (!nodeId || !tokenHeader || !panelSecretHeader || !ts || !nonce || !sig || !rsaSig) {
    return null;
  }

  const nodes = await readJson(nodesFile, []);
  const node = nodes.find((item) => item.id === nodeId);
  if (!node) {
    return null;
  }

  const token = node.token || node.secret;
  const panelSecret = node.panelSecret || node.agentSecret || node.secret;
  if (!token || tokenHeader !== token) {
    return null;
  }
  if (panelSecretHeader !== panelSecret) {
    return null;
  }

  if (!isFresh(ts)) {
    return null;
  }

  const replayKey = `${ts}:${nonce}`;
  if (replaySet.has(replayKey)) {
    return null;
  }
  replaySet.add(replayKey);
  replayQueue.push(replayKey);
  if (replayQueue.length > REPLAY_LIMIT) {
    const oldest = replayQueue.shift();
    if (oldest) replaySet.delete(oldest);
  }

  const payload = req.body && typeof req.body === "object" ? req.body : {};
  const canonicalPayload = canonical(req.method, req.path, ts, nonce, payload);

  if (!verifyHmac(canonicalPayload, token, sig)) {
    return null;
  }

  if (node.publicKey && !verifyRsa(canonicalPayload, rsaSig, node.publicKey)) {
    return null;
  }

  return node;
}

function getLocalVersion() {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(baseDir, "package.json"), "utf8"));
    return String(pkg.version || "0.0.0");
  } catch {
    return "0.0.0";
  }
}

function issueAuthCookieHeader(token) {
  const secureFlag = process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
  return [
    `nodewings_token=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${TOKEN_TTL_SECONDS}`,
  ].join("; ") + secureFlag;
}

function clearAuthCookieHeader() {
  const secureFlag = process.env.COOKIE_SECURE === "true" ? "; Secure" : "";
  return "nodewings_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" + secureFlag;
}

function normalizeTheme(value, fallback = DEFAULT_THEMES[0].id) {
  return normalizeThemeId(value, DEFAULT_THEMES, fallback);
}

function normalizeServerLimit(value, fallback = 1) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  const rounded = Math.trunc(parsed);
  if (rounded < -1) {
    return fallback;
  }
  return rounded;
}

function isHexColor(value) {
  return /^#[0-9a-fA-F]{6}$/.test(String(value || ""));
}

function isValidUrl(value) {
  try {
    const parsed = new URL(String(value));
    return ["http:", "https:"].includes(parsed.protocol);
  } catch {
    return false;
  }
}

const PALETTE_KEYS = [
  "background",
  "sidebar",
  "card",
  "text",
  "muted",
  "line",
  "input_bg",
  "input_text",
  "table_head",
  "hover_bg",
  "accent",
  "button",
];

function sanitizePalette(input, fallback) {
  const source = input && typeof input === "object" ? input : {};
  const base = fallback && typeof fallback === "object" ? fallback : {};
  const palette = {};
  for (const key of PALETTE_KEYS) {
    const raw = source[key] ?? base[key];
    if (typeof raw === "string" && raw.trim()) {
      palette[key] = raw.trim();
    } else if (typeof base[key] === "string") {
      palette[key] = base[key];
    }
  }
  return palette;
}

function sanitizeThemeRecord(theme, fallbackPalette) {
  if (!theme || typeof theme !== "object") return null;
  const id = String(theme.id || "").trim().toLowerCase();
  if (!id || !THEME_ID_PATTERN.test(id)) {
    return null;
  }
  const name = String(theme.name || id).trim() || id;
  const palette = sanitizePalette(theme.palette, fallbackPalette);
  if (Object.keys(palette).length === 0) {
    return null;
  }
  return {
    id,
    name,
    locked: Boolean(theme.locked),
    palette,
  };
}

function extractPaletteUpdates(body) {
  const updates = {};
  if (!body || typeof body !== "object") {
    return updates;
  }
  const palette = body.palette && typeof body.palette === "object" ? body.palette : {};
  for (const key of PALETTE_KEYS) {
    const raw = palette[key] ?? body[key];
    if (typeof raw === "string" && raw.trim()) {
      updates[key] = raw.trim();
    }
  }
  return updates;
}

async function ensureThemes() {
  const fallbackPalette = DEFAULT_THEMES[0].palette;
  const stored = await readJson(themesFile, DEFAULT_THEMES);
  const list = Array.isArray(stored) ? stored : [];
  const sanitized = list
    .map((theme) => sanitizeThemeRecord(theme, fallbackPalette))
    .filter(Boolean);

  const byId = new Map(sanitized.map((theme) => [theme.id, theme]));
  for (const theme of DEFAULT_THEMES) {
    if (!byId.has(theme.id)) {
      byId.set(theme.id, theme);
    }
  }

  const merged = Array.from(byId.values());
  await updateJson(themesFile, DEFAULT_THEMES, () => merged);
  return merged;
}

async function readThemes() {
  const stored = await readJson(themesFile, DEFAULT_THEMES);
  if (!Array.isArray(stored) || stored.length === 0) {
    return DEFAULT_THEMES;
  }
  const fallbackPalette = DEFAULT_THEMES[0].palette;
  const sanitized = stored
    .map((theme) => sanitizeThemeRecord(theme, fallbackPalette))
    .filter(Boolean);
  if (sanitized.length === 0) {
    return DEFAULT_THEMES;
  }
  return sanitized;
}

function normalizeThemeId(value, themes, fallbackId = DEFAULT_THEMES[0].id) {
  const candidate = String(value || "").trim().toLowerCase();
  const ids = new Set((themes || []).map((theme) => theme.id));
  if (ids.has(candidate)) {
    return candidate;
  }
  return fallbackId;
}

function resolveThemeById(themes, id) {
  return (themes || []).find((theme) => theme.id === id) || null;
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  return req.socket.remoteAddress || "unknown";
}

const API_KEY_PERMISSIONS = new Set(["all", "servers", "nodes", "users", "panel"]);

function generateApiKey() {
  const raw = crypto.randomBytes(18).toString("base64").replace(/[^a-zA-Z0-9]/g, "");
  return `dra_${raw.slice(0, 24)}`;
}

function maskApiKey(key) {
  const value = String(key || "");
  if (value.length <= 10) {
    return value;
  }
  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}

function normalizePermissions(input) {
  const list = Array.isArray(input) ? input : [];
  const cleaned = list
    .map((item) => String(item || "").trim().toLowerCase())
    .filter((item) => API_KEY_PERMISSIONS.has(item));

  if (cleaned.includes("all")) {
    return ["all"];
  }

  return Array.from(new Set(cleaned));
}

function requireApiKey(allowed = []) {
  const required = Array.isArray(allowed) ? allowed : [];

  return async (req, res, next) => {
    const auth = String(req.headers.authorization || "");
    const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    if (!token || !token.startsWith("dra_")) {
      return res.status(401).json({ error: "Missing API key" });
    }

    const keys = await readJson(apiKeysFile, []);
    const record = keys.find((item) => item.key === token);
    if (!record) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    const perms = Array.isArray(record.permissions) ? record.permissions : [];
    const ok =
      perms.includes("all") ||
      required.length === 0 ||
      required.some((perm) => perms.includes(perm));

    if (!ok) {
      return res.status(403).json({ error: "API key lacks permission" });
    }

    req.apiKey = record;
    return next();
  };
}

function createRateLimiter({
  windowMs,
  max,
  keyFn = (req) => getClientIp(req),
  skip = () => false,
}) {
  const bucket = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of bucket.entries()) {
      if (entry.resetAt <= now) {
        bucket.delete(key);
      }
    }
  }, Math.max(windowMs, 1000));

  return (req, res, next) => {
    if (skip(req)) {
      return next();
    }

    const now = Date.now();
    const key = keyFn(req);
    const current = bucket.get(key);

    if (!current || current.resetAt <= now) {
      bucket.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }

    current.count += 1;
    if (current.count > max) {
      return res.status(429).json({ error: "Too many requests" });
    }

    return next();
  };
}

function sanitizeNode(node) {
  const clone = { ...node };
  delete clone.secret;
  delete clone.token;
  delete clone.panelSecret;
  delete clone.agentSecret;
  delete clone.publicKey;
  return clone;
}

function sendForbiddenPage(res) {
  res.status(403).sendFile(path.join(publicDir, "403.html"));
}

function toThemePayload(settings, themes = DEFAULT_THEMES) {
  return {
    default_theme: normalizeThemeId(
      settings.default_theme,
      themes,
      DEFAULT_PANEL_SETTINGS.default_theme
    ),
    button_color: isHexColor(settings.button_color)
      ? settings.button_color
      : DEFAULT_PANEL_SETTINGS.button_color,
    sidebar_color: isHexColor(settings.sidebar_color)
      ? settings.sidebar_color
      : DEFAULT_PANEL_SETTINGS.sidebar_color,
    card_color: isHexColor(settings.card_color)
      ? settings.card_color
      : DEFAULT_PANEL_SETTINGS.card_color,
    background_image:
      typeof settings.background_image === "string" ? settings.background_image : DEFAULT_PANEL_SETTINGS.background_image,
    default_server_limit: normalizeServerLimit(
      settings.default_server_limit,
      DEFAULT_PANEL_SETTINGS.default_server_limit
    ),
  };
}

async function readPanelSettings() {
  const [settings, themes] = await Promise.all([
    readJson(panelSettingsFile, DEFAULT_PANEL_SETTINGS),
    readThemes(),
  ]);
  return toThemePayload(settings, themes);
}

async function resolveNode(nodeId) {
  const nodes = await readJson(nodesFile, []);
  return nodes.find((node) => node.id === nodeId) || null;
}

async function resolveServer(uuid) {
  const servers = await readJson(serversFile, []);
  return servers.find((item) => item.uuid === uuid) || null;
}

async function getUserRecordById(id) {
  const users = await readJson(usersFile, []);
  return users.find((item) => item.id === id) || null;
}

function getEffectiveServerLimit(userRecord, panelSettings) {
  const userLimit = normalizeServerLimit(userRecord?.server_limit, NaN);
  if (Number.isFinite(userLimit) && userLimit >= -1) {
    return userLimit;
  }
  return normalizeServerLimit(
    panelSettings.default_server_limit,
    DEFAULT_PANEL_SETTINGS.default_server_limit
  );
}

function countOwnedServers(servers, userId) {
  return servers.filter((item) => item.createdBy === userId).length;
}

function assertServerAccess(user, targetServer) {
  if (!targetServer) {
    throw Object.assign(new Error("Server not found"), { statusCode: 404 });
  }

  if (user.role === "admin") {
    return;
  }

  if (targetServer.createdBy !== user.id) {
    throw Object.assign(new Error("Forbidden"), { statusCode: 403 });
  }
}

async function resolveAuthUserFromToken(token) {
  if (!token) {
    return null;
  }

  try {
    const decoded = verifyToken(token);
    const [sessions, users] = await Promise.all([
      readJson(sessionsFile, []),
      readJson(usersFile, []),
    ]);

    const session = sessions.find((item) => item.sid === decoded.sid);
    if (!session) {
      return null;
    }

    if (new Date(session.expiresAt).getTime() <= Date.now()) {
      return null;
    }

    const user = users.find((item) => item.id === decoded.sub);
    if (!user) {
      return null;
    }

    return sanitizeUser(user);
  } catch {
    return null;
  }
}

async function requireAdminPage(req, res, next) {
  const token = getBearerToken(req);
  const user = await resolveAuthUserFromToken(token);
  if (!user || user.role !== "admin") {
    return sendForbiddenPage(res);
  }

  req.user = user;
  return next();
}

function pushServerEvent(uuid, event) {
  if (!serverEvents.has(uuid)) {
    serverEvents.set(uuid, []);
  }
  const list = serverEvents.get(uuid);
  list.push(event);
  if (list.length > 3000) {
    list.splice(0, list.length - 3000);
  }
}

async function appendAuditLog(entry) {
  await updateJson(logsFile, [], (logs) => {
    logs.push({
      id: crypto.randomUUID(),
      ts: nowIso(),
      ...entry,
    });

    if (logs.length > 5000) {
      logs.splice(0, logs.length - 5000);
    }

    return logs;
  });
}

function parseVersion(value) {
  const match = String(value || "").trim().match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
  };
}

function compareVersions(a, b) {
  if (!a || !b) return 0;
  if (a.major !== b.major) return a.major > b.major ? 1 : -1;
  if (a.minor !== b.minor) return a.minor > b.minor ? 1 : -1;
  if (a.patch !== b.patch) return a.patch > b.patch ? 1 : -1;
  return 0;
}

function extractVersions(text) {
  const matches = String(text || "").match(/\d+\.\d+\.\d+/g);
  return matches ? Array.from(new Set(matches)) : [];
}

function pickLatestVersion(values) {
  let best = null;
  for (const value of values) {
    const parsed = parseVersion(value);
    if (!parsed) continue;
    if (!best || compareVersions(parsed, best.parsed) > 0) {
      best = { value, parsed };
    }
  }
  return best ? best.value : null;
}

async function fetchRemoteVersion(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(url, { signal: controller.signal });
    const text = await response.text();
    const versions = extractVersions(text);
    const latest = pickLatestVersion(versions);
    if (!latest) {
      throw new Error("No version found at remote URL");
    }
    return latest;
  } finally {
    clearTimeout(timer);
  }
}

async function readUpdateState() {
  return readJson(updateStateFile, DEFAULT_UPDATE_STATE);
}

async function writeUpdateState(patch) {
  return updateJson(updateStateFile, DEFAULT_UPDATE_STATE, (state) => ({
    ...DEFAULT_UPDATE_STATE,
    ...(state || {}),
    ...(patch || {}),
  }));
}

function execCommand(command, cwd) {
  return new Promise((resolve, reject) => {
    exec(command, { cwd, windowsHide: true }, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

async function runGitUpdate(targetDir) {
  if (!fs.existsSync(path.join(targetDir, ".git"))) {
    return { ok: false, skipped: true, reason: "Not a git repository" };
  }

  const status = await execCommand("git status --porcelain", targetDir);
  if (String(status.stdout || "").trim()) {
    return { ok: false, skipped: true, reason: "Working tree has uncommitted changes" };
  }

  const pull = await execCommand("git pull --ff-only", targetDir);
  return { ok: true, output: `${pull.stdout || ""}${pull.stderr || ""}`.trim() };
}

async function setServerStatus(uuid, status, extra = {}) {
  await updateJson(serversFile, [], (servers) => {
    return servers.map((item) => {
      if (item.uuid !== uuid) {
        return item;
      }
      return {
        ...item,
        status,
        updatedAt: nowIso(),
        ...extra,
      };
    });
  });
}

async function verifyInternalNode(req) {
  const nodeId = req.headers["x-node-id"];
  const secret = req.headers["x-node-secret"];
  if (!nodeId || !secret) {
    return null;
  }

  const nodes = await readJson(nodesFile, []);
  const node = nodes.find((item) => item.id === nodeId);
  if (!node) {
    return null;
  }

  if (node.secret !== secret) {
    return null;
  }

  return node;
}

async function callServerNode(user, uuid, payload) {
  const targetServer = await resolveServer(uuid);
  assertServerAccess(user, targetServer);
  const action = payload?.action;
  if (
    targetServer?.suspended &&
    ["start_server", "restart_server", "exec_server"].includes(action)
  ) {
    throw Object.assign(new Error("Server is suspended"), { statusCode: 403 });
  }

  const node = await resolveNode(targetServer.nodeId);
  if (!node) {
    throw Object.assign(new Error("Assigned node not found"), { statusCode: 404 });
  }

  const result = await callNodeCommand(node, {
    ...payload,
    server: targetServer,
  });

  return {
    targetServer,
    node,
    result,
  };
}

async function callServerNodeWithApiKey(uuid, payload) {
  const targetServer = await resolveServer(uuid);
  if (!targetServer) {
    throw Object.assign(new Error("Server not found"), { statusCode: 404 });
  }
  const action = payload?.action;
  if (
    targetServer?.suspended &&
    ["start_server", "restart_server", "exec_server"].includes(action)
  ) {
    throw Object.assign(new Error("Server is suspended"), { statusCode: 403 });
  }

  const node = await resolveNode(targetServer.nodeId);
  if (!node) {
    throw Object.assign(new Error("Assigned node not found"), { statusCode: 404 });
  }

  const result = await callNodeCommand(node, {
    ...payload,
    server: targetServer,
  });

  return {
    targetServer,
    node,
    result,
  };
}

function buildRuntime(value) {
  const runtime = String(value || "").toLowerCase();
  if (runtime === "node" || runtime === "python" || runtime === "java") {
    return runtime;
  }
  return null;
}

function validateServerCreateInput(body) {
  const errors = [];

  const name = String(body?.name || "").trim();
  if (!name) {
    errors.push("name is required");
  }

  const nodeId = String(body?.nodeId || "").trim();
  if (!nodeId) {
    errors.push("nodeId is required");
  }

  const runtime = buildRuntime(body?.runtime);
  if (!runtime) {
    errors.push("runtime must be node, python, or java");
  }

  const ramLimitMb = Number(body?.ramLimitMb ?? 512);
  if (!Number.isFinite(ramLimitMb) || ramLimitMb < 32 || ramLimitMb > 1048576) {
    errors.push("ramLimitMb must be between 32 and 1048576");
  }

  const cpuLimitPercent = Number(body?.cpuLimitPercent ?? 100);
  if (!Number.isFinite(cpuLimitPercent) || cpuLimitPercent < 1 || cpuLimitPercent > 10000) {
    errors.push("cpuLimitPercent must be between 1 and 10000");
  }

  if (errors.length > 0) {
    return { errors };
  }

  return {
    name,
    nodeId,
    runtime,
    runtimeVersion: body?.runtimeVersion ? String(body.runtimeVersion).trim() : null,
    templateId: body?.templateId ? String(body.templateId).trim() : null,
    entryFile: String(
      body?.entryFile ||
        (runtime === "node" ? "index.js" : runtime === "java" ? "server.jar" : "app.py")
    ).trim(),
    startCommand: body?.startCommand ? String(body.startCommand).trim() : null,
    ramLimitMb,
    cpuLimitPercent,
    autoRestart: body?.autoRestart !== false,
    autoStart: body?.autoStart !== false,
  };
}

function resolveDockerImage(runtime, runtimeVersion, versions = DEFAULT_RUNTIME_VERSIONS) {
  const pick = (list) => (Array.isArray(list) && list.length > 0 ? list[0] : null);
  const version =
    runtimeVersion ||
    (runtime === "node" ? pick(versions.node) : runtime === "python" ? pick(versions.python) : pick(versions.java));
  if (runtime === "node") {
    return version ? `node:${version}-alpine` : "node:20-alpine";
  }
  if (runtime === "python") {
    return version ? `python:${version}-alpine` : "python:3.11-alpine";
  }
  if (runtime === "java") {
    return version ? `eclipse-temurin:${version}-jdk` : "eclipse-temurin:17-jdk";
  }
  return null;
}

function createServerRecord(input, userId) {
  const createdAt = nowIso();
  return {
    uuid: crypto.randomUUID(),
    name: input.name,
    nodeId: input.nodeId,
    runtime: input.runtime,
    runtimeVersion: input.runtimeVersion || null,
    templateId: input.templateId || null,
    image: input.image || null,
    entryFile: input.entryFile,
    startCommand: input.startCommand,
    ramLimitMb: Number(input.ramLimitMb),
    cpuLimitPercent: Number(input.cpuLimitPercent),
    autoRestart: input.autoRestart !== false,
    suspended: false,
    status: "creating",
    createdAt,
    updatedAt: createdAt,
    createdBy: userId,
    lastExit: null,
    resources: {
      cpuPercent: 0,
      ramMb: 0,
    },
  };
}

function createHttpServer(appInstance) {
  if (process.env.HTTPS_ENABLED !== "true") {
    return http.createServer(appInstance);
  }

  const keyPath = process.env.HTTPS_KEY_PATH;
  const certPath = process.env.HTTPS_CERT_PATH;

  if (!keyPath || !certPath) {
    console.warn("HTTPS_ENABLED=true but key/cert path missing. Falling back to HTTP.");
    return http.createServer(appInstance);
  }

  try {
    const key = fs.readFileSync(keyPath, "utf8");
    const cert = fs.readFileSync(certPath, "utf8");
    return https.createServer({ key, cert }, appInstance);
  } catch (error) {
    console.warn(`Failed to read HTTPS certs (${error.message}). Falling back to HTTP.`);
    return http.createServer(appInstance);
  }
}

const server = createHttpServer(app);
const wsHub = createWsHub({
  server,
  verifyClient: resolveAuthUserFromToken,
});

async function ensureBootstrapData() {
  ensurePanelKeys();
  const defaultAdminEmail = process.env.DEFAULT_ADMIN_EMAIL || "admin@example.com";
  const defaultAdminPassword = process.env.DEFAULT_ADMIN_PASSWORD || "admin123";

  const themes = await ensureThemes();
  const settings = await updateJson(panelSettingsFile, DEFAULT_PANEL_SETTINGS, (current) => {
    return {
      ...DEFAULT_PANEL_SETTINGS,
      ...toThemePayload(current, themes),
      default_server_limit: normalizeServerLimit(
        current.default_server_limit,
        DEFAULT_PANEL_SETTINGS.default_server_limit
      ),
    };
  });

  await updateJson(usersFile, [], (users) => {
    if (users.length === 0) {
      users.push({
        id: "u-admin",
        name: "Administrator",
        email: defaultAdminEmail.toLowerCase(),
        role: "admin",
        passwordHash: hashPassword(defaultAdminPassword),
        server_limit: -1,
        theme: settings.default_theme,
        createdAt: nowIso(),
      });
      return users;
    }

    return users.map((user) => {
      return {
        ...user,
        role: user.role === "admin" ? "admin" : "user",
        theme: normalizeThemeId(user.theme, themes, settings.default_theme),
        server_limit: normalizeServerLimit(user.server_limit, settings.default_server_limit),
      };
    });
  });

  await updateJson(nodesFile, [], (nodes) => {
    if (nodes.length > 0) {
      return nodes;
    }
    const defaultSecret = process.env.DEFAULT_NODE_SECRET || "nodewings-shared-secret";
    const defaultToken = process.env.DEFAULT_NODE_TOKEN || defaultSecret;
    nodes.push({
      id: "node-1",
      name: "Primary Node",
      url: "http://127.0.0.1:8080",
      secret: defaultSecret,
      token: defaultToken,
      panelSecret: defaultSecret,
      agentSecret: defaultSecret,
      protocol: "signed",
      status: "offline",
      lastHeartbeat: null,
      resources: {},
    });
    return nodes;
  });

  await updateJson(nodesFile, [], (nodes) =>
    nodes.map((node) => ({
      ...node,
      token: node.token || node.secret || "",
      panelSecret: node.panelSecret || node.secret || "",
      agentSecret: node.agentSecret || node.secret || "",
      protocol: node.protocol || "signed",
    }))
  );

  await updateJson(apiKeysFile, [], (keys) => (Array.isArray(keys) ? keys : []));
  await updateJson(updateStateFile, DEFAULT_UPDATE_STATE, (state) => ({
    ...DEFAULT_UPDATE_STATE,
    ...(state || {}),
  }));
  await updateJson(runtimeVersionsFile, DEFAULT_RUNTIME_VERSIONS, (versions) => {
    if (!versions || typeof versions !== "object") {
      return DEFAULT_RUNTIME_VERSIONS;
    }
    return {
      node: Array.isArray(versions.node) && versions.node.length > 0 ? versions.node : DEFAULT_RUNTIME_VERSIONS.node,
      python:
        Array.isArray(versions.python) && versions.python.length > 0
          ? versions.python
          : DEFAULT_RUNTIME_VERSIONS.python,
      java:
        Array.isArray(versions.java) && versions.java.length > 0
          ? versions.java
          : DEFAULT_RUNTIME_VERSIONS.java,
    };
  });

  await updateJson(sessionsFile, [], (sessions) => sessions);
  await updateJson(serversFile, [], (servers) =>
    servers.map((server) => {
      const runtime = server.runtime || "node";
      const runtimeVersion = server.runtimeVersion ?? null;
      const image = server.image || resolveDockerImage(runtime, runtimeVersion, DEFAULT_RUNTIME_VERSIONS);
      return {
        ...server,
        suspended: Boolean(server.suspended),
        runtimeVersion,
        templateId: server.templateId ?? null,
        image,
        autoRestart: server.autoRestart !== false,
      };
    })
  );
  await updateJson(logsFile, [], (logs) => logs);
}

app.disable("x-powered-by");
app.use(express.json({ limit: "200mb" }));
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

const apiLimiter = createRateLimiter({
  windowMs: 60 * 1000,
  max: 300,
  keyFn: (req) => `${getClientIp(req)}:${req.path}`,
  skip: (req) => req.path.startsWith("/internal/"),
});

const loginLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000,
  max: 20,
  keyFn: (req) => `${getClientIp(req)}:login`,
});

app.use("/api", apiLimiter);
app.use("/api/v1", apiLimiter);
app.use(express.static(publicDir));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", ts: nowIso() });
});

app.get("/api/panel-settings", async (_req, res) => {
  const [settings, themes] = await Promise.all([readPanelSettings(), readThemes()]);
  const theme = resolveThemeById(themes, settings.default_theme) || themes[0] || null;
  res.json({ settings, theme, themes });
});

app.get("/api/themes", attachUser, async (_req, res) => {
  const themes = await readThemes();
  res.json({ themes });
});

app.get("/api/runtime-versions", attachUser, async (_req, res) => {
  const versions = await readJson(runtimeVersionsFile, DEFAULT_RUNTIME_VERSIONS);
  res.json({ versions });
});

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  const email = String(req.body?.email || "").toLowerCase().trim();
  const password = String(req.body?.password || "");

  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  const users = await readJson(usersFile, []);
  const user = users.find((item) => item.email.toLowerCase() === email);
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const { token, sid, expiresAt } = issueToken(user);
  await updateJson(sessionsFile, [], (sessions) => {
    sessions.push({
      sid,
      userId: user.id,
      issuedAt: nowIso(),
      expiresAt,
      ip: getClientIp(req),
    });
    return sessions;
  });

  await appendAuditLog({
    type: "auth.login",
    actorId: user.id,
    actorEmail: user.email,
  });

  res.setHeader("Set-Cookie", issueAuthCookieHeader(token));

  return res.json({
    token,
    expiresAt,
    user: sanitizeUser(user),
  });
});

app.post("/api/auth/logout", attachUser, async (req, res) => {
  await updateJson(sessionsFile, [], (sessions) => {
    return sessions.filter((item) => item.sid !== req.session.sid);
  });

  await appendAuditLog({
    type: "auth.logout",
    actorId: req.user.id,
    actorEmail: req.user.email,
  });

  res.setHeader("Set-Cookie", clearAuthCookieHeader());
  res.json({ ok: true });
});

app.get("/api/auth/me", attachUser, async (req, res) => {
  res.json({ user: req.user });
});

app.get("/api/settings", attachUser, async (req, res) => {
  const [settings, user, themes] = await Promise.all([
    readPanelSettings(),
    getUserRecordById(req.user.id),
    readThemes(),
  ]);
  const currentThemeId = normalizeThemeId(
    user?.theme || req.user.theme,
    themes,
    settings.default_theme
  );
  const theme = resolveThemeById(themes, currentThemeId) || themes[0] || null;
  res.json({
    settings,
    user: sanitizeUser({ ...(user || req.user), theme: currentThemeId }),
    theme,
    themes,
  });
});

app.put("/api/settings/theme", attachUser, async (req, res) => {
  const themes = await readThemes();
  const theme = normalizeThemeId(req.body?.theme, themes, "");
  if (!theme) {
    return res.status(400).json({ error: "Unknown theme" });
  }

  let updated = null;
  await updateJson(usersFile, [], (users) => {
    return users.map((user) => {
      if (user.id !== req.user.id) {
        return user;
      }
      updated = { ...user, theme };
      return updated;
    });
  });

  if (!updated) {
    return res.status(404).json({ error: "User not found" });
  }

  await appendAuditLog({
    type: "settings.theme.update",
    actorId: req.user.id,
    actorEmail: req.user.email,
    theme,
  });

  res.json({ user: sanitizeUser(updated) });
});

app.get("/api/dashboard", attachUser, async (req, res) => {
  const [servers, nodes] = await Promise.all([
    readJson(serversFile, []),
    readJson(nodesFile, []),
  ]);

  const visibleServers = req.user.role === "admin"
    ? servers
    : servers.filter((item) => item.createdBy === req.user.id);

  const onlineNodes = nodes.filter((node) => node.status === "online").length;
  const runningServers = visibleServers.filter((item) => item.status === "running").length;

  const cpuAverage =
    nodes.length === 0
      ? 0
      : Number(
          (
            nodes.reduce((sum, node) => sum + Number(node.resources?.cpuPercent || 0), 0) /
            nodes.length
          ).toFixed(2)
        );

  const ramAverage =
    nodes.length === 0
      ? 0
      : Number(
          (
            nodes.reduce((sum, node) => sum + Number(node.resources?.ramUsedPercent || 0), 0) /
            nodes.length
          ).toFixed(2)
        );

  res.json({
    totalServers: visibleServers.length,
    runningServers,
    totalNodes: nodes.length,
    onlineNodes,
    cpuAverage,
    ramAverage,
    generatedAt: nowIso(),
  });
});

app.get("/api/nodes", attachUser, async (_req, res) => {
  const nodes = await readJson(nodesFile, []);
  res.json({ nodes: nodes.map(sanitizeNode) });
});

app.get("/api/servers", attachUser, async (req, res) => {
  const servers = await readJson(serversFile, []);
  const list = req.user.role === "admin"
    ? servers
    : servers.filter((item) => item.createdBy === req.user.id);
  res.json({ servers: list });
});

app.get("/api/servers/:uuid", attachUser, async (req, res) => {
  const { uuid } = req.params;
  try {
    const targetServer = await resolveServer(uuid);
    assertServerAccess(req.user, targetServer);
    res.json({ server: targetServer });
  } catch (error) {
    const statusCode = Number(error.statusCode) || 404;
    res.status(statusCode).json({ error: error.message });
  }
});

app.patch("/api/servers/:uuid", attachUser, async (req, res) => {
  const { uuid } = req.params;
  const targetServer = await resolveServer(uuid);
  try {
    assertServerAccess(req.user, targetServer);
  } catch (error) {
    const statusCode = Number(error.statusCode) || 403;
    return res.status(statusCode).json({ error: error.message });
  }

  const isAdmin = req.user.role === "admin";
  const patch = {};

  if (req.body?.name !== undefined) {
    const name = String(req.body.name || "").trim();
    if (!name) {
      return res.status(400).json({ error: "name cannot be empty" });
    }
    patch.name = name;
  }

  if (req.body?.entryFile !== undefined) {
    const entryFile = String(req.body.entryFile || "").trim();
    if (!entryFile) {
      return res.status(400).json({ error: "entryFile cannot be empty" });
    }
    patch.entryFile = entryFile;
  }

  if (req.body?.startCommand !== undefined) {
    const startCommand = String(req.body.startCommand || "").trim();
    patch.startCommand = startCommand || null;
  }

  if (req.body?.autoRestart !== undefined) {
    patch.autoRestart = Boolean(req.body.autoRestart);
  }

  if (req.body?.ramLimitMb !== undefined) {
    if (!isAdmin) {
      return res.status(403).json({ error: "Only admins can change RAM limits" });
    }
    const ramLimitMb = Number(req.body.ramLimitMb);
    if (!Number.isFinite(ramLimitMb) || ramLimitMb < 32 || ramLimitMb > 1048576) {
      return res.status(400).json({ error: "ramLimitMb must be between 32 and 1048576" });
    }
    patch.ramLimitMb = ramLimitMb;
  }

  if (req.body?.cpuLimitPercent !== undefined) {
    if (!isAdmin) {
      return res.status(403).json({ error: "Only admins can change CPU limits" });
    }
    const cpuLimitPercent = Number(req.body.cpuLimitPercent);
    if (!Number.isFinite(cpuLimitPercent) || cpuLimitPercent < 1 || cpuLimitPercent > 10000) {
      return res.status(400).json({ error: "cpuLimitPercent must be between 1 and 10000" });
    }
    patch.cpuLimitPercent = cpuLimitPercent;
  }

  if (req.body?.suspended !== undefined) {
    if (!isAdmin) {
      return res.status(403).json({ error: "Only admins can suspend servers" });
    }
    patch.suspended = Boolean(req.body.suspended);
  }

  if (Object.keys(patch).length === 0) {
    return res.status(400).json({ error: "No valid fields to update" });
  }

  let updated = null;
  await updateJson(serversFile, [], (servers) =>
    servers.map((server) => {
      if (server.uuid !== uuid) {
        return server;
      }
      updated = {
        ...server,
        ...patch,
        status:
          patch.suspended === true
            ? "suspended"
            : patch.suspended === false && server.status === "suspended"
              ? "stopped"
              : server.status,
        updatedAt: nowIso(),
      };
      return updated;
    })
  );

  if (!updated) {
    return res.status(404).json({ error: "Server not found" });
  }

  if (patch.suspended === true) {
    try {
      const node = await resolveNode(updated.nodeId);
      if (node) {
        await callNodeCommand(node, { action: "stop_server", server: updated });
      }
    } catch (error) {
      // Ignore stop failures; suspension still applies.
    }
  }

  await appendAuditLog({
    type: patch.suspended === true ? "server.suspend" : patch.suspended === false ? "server.unsuspend" : "server.update",
    actorId: req.user.id,
    actorEmail: req.user.email,
    serverUuid: uuid,
    updates: patch,
  });

  res.json({ server: updated });
});

app.delete("/api/servers/:uuid", attachUser, async (req, res) => {
  const { uuid } = req.params;
  let targetServer = null;
  try {
    targetServer = await resolveServer(uuid);
    assertServerAccess(req.user, targetServer);
  } catch (error) {
    const statusCode = Number(error.statusCode) || 404;
    return res.status(statusCode).json({ error: error.message });
  }

  try {
    const node = await resolveNode(targetServer.nodeId);
    if (node) {
      await callNodeCommand(node, { action: "delete_server", server: targetServer });
    }
  } catch (error) {
    return res.status(502).json({ error: error.message });
  }

  await updateJson(serversFile, [], (servers) => servers.filter((item) => item.uuid !== uuid));

  await appendAuditLog({
    type: "server.delete",
    actorId: req.user.id,
    actorEmail: req.user.email,
    serverUuid: uuid,
    nodeId: targetServer.nodeId,
  });

  res.json({ ok: true });
});

app.post("/api/servers", attachUser, async (req, res) => {
  const valid = validateServerCreateInput(req.body);
  if (valid.errors) {
    return res.status(400).json({ error: valid.errors.join("; ") });
  }

  const node = await resolveNode(valid.nodeId);
  if (!node) {
    return res.status(404).json({ error: "Node not found" });
  }

  const [settings, servers, userRecord] = await Promise.all([
    readPanelSettings(),
    readJson(serversFile, []),
    getUserRecordById(req.user.id),
  ]);

  if (!userRecord) {
    return res.status(404).json({ error: "User not found" });
  }

  const limit = getEffectiveServerLimit(userRecord, settings);
  const ownedCount = countOwnedServers(servers, req.user.id);
  if (limit !== -1 && ownedCount >= limit) {
    return res.status(400).json({ error: "Server limit reached." });
  }

  const versions = await readJson(runtimeVersionsFile, DEFAULT_RUNTIME_VERSIONS);
  const list = Array.isArray(versions[valid.runtime]) ? versions[valid.runtime] : [];
  if (valid.runtimeVersion && list.length > 0 && !list.includes(valid.runtimeVersion)) {
    return res.status(400).json({ error: "Unsupported runtime version" });
  }

  const image = resolveDockerImage(valid.runtime, valid.runtimeVersion, versions);
  if (!image) {
    return res.status(400).json({ error: "Unsupported runtime image" });
  }

  const serverRecord = createServerRecord({ ...valid, image }, req.user.id);

  await updateJson(serversFile, [], (list) => {
    list.push(serverRecord);
    return list;
  });

  try {
    await callNodeCommand(node, {
      action: "create_server",
      server: serverRecord,
    });

    if (valid.autoStart !== false) {
      await callNodeCommand(node, {
        action: "start_server",
        server: serverRecord,
      });
      await setServerStatus(serverRecord.uuid, "starting");
    } else {
      await setServerStatus(serverRecord.uuid, "stopped");
    }

    await appendAuditLog({
      type: "server.create",
      actorId: req.user.id,
      actorEmail: req.user.email,
      serverUuid: serverRecord.uuid,
      nodeId: valid.nodeId,
    });

    res.status(201).json({
      server: {
        ...serverRecord,
        status: valid.autoStart !== false ? "starting" : "stopped",
      },
    });
  } catch (error) {
    await setServerStatus(serverRecord.uuid, "error", {
      error: error.message,
    });

    res.status(502).json({ error: error.message });
  }
});

app.post("/api/servers/:uuid/actions/:action", attachUser, async (req, res) => {
  const { uuid, action } = req.params;
  const actionMap = {
    start: "start_server",
    stop: "stop_server",
    restart: "restart_server",
    kill: "kill_server",
  };

  const mapped = actionMap[action];
  if (!mapped) {
    return res.status(400).json({ error: "Unsupported action" });
  }

  try {
    const { result, targetServer } = await callServerNode(req.user, uuid, {
      action: mapped,
    });

    const statusMap = {
      start: "starting",
      stop: "stopping",
      restart: "restarting",
      kill: "stopping",
    };

    await setServerStatus(uuid, statusMap[action] || "unknown");

    await appendAuditLog({
      type: `server.${action}`,
      actorId: req.user.id,
      actorEmail: req.user.email,
      serverUuid: uuid,
      nodeId: targetServer.nodeId,
    });

    res.json({ ok: true, result });
  } catch (error) {
    const statusCode = Number(error.statusCode) || 502;
    res.status(statusCode).json({ error: error.message });
  }
});

app.post("/api/servers/:uuid/console", attachUser, async (req, res) => {
  const { uuid } = req.params;
  const command = String(req.body?.command || "").trim();
  if (!command) {
    return res.status(400).json({ error: "command is required" });
  }

  try {
    const { result } = await callServerNode(req.user, uuid, {
      action: "exec_server",
      command,
    });

    res.json({ ok: true, result });
  } catch (error) {
    const statusCode = Number(error.statusCode) || 502;
    res.status(statusCode).json({ error: error.message });
  }
});

app.get("/api/servers/:uuid/events", attachUser, async (req, res) => {
  const { uuid } = req.params;
  const limit = Math.max(1, Math.min(Number(req.query.limit || 200), 1000));

  try {
    const targetServer = await resolveServer(uuid);
    assertServerAccess(req.user, targetServer);

    const events = serverEvents.get(uuid) || [];
    res.json({ events: events.slice(-limit) });
  } catch (error) {
    const statusCode = Number(error.statusCode) || 500;
    res.status(statusCode).json({ error: error.message });
  }
});

app.get("/api/servers/:uuid/resources", attachUser, async (req, res) => {
  const { uuid } = req.params;

  try {
    const targetServer = await resolveServer(uuid);
    assertServerAccess(req.user, targetServer);

    const events = (serverEvents.get(uuid) || []).filter((event) => event.type === "resource");
    const latest = events.at(-1)?.payload || null;
    res.json({ resource: latest, historyCount: events.length });
  } catch (error) {
    const statusCode = Number(error.statusCode) || 500;
    res.status(statusCode).json({ error: error.message });
  }
});

async function forwardFileAction(req, res, action) {
  const { uuid } = req.params;

  try {
    const serverRecord = await resolveServer(uuid);
    assertServerAccess(req.user, serverRecord);

    const node = await resolveNode(serverRecord.nodeId);
    if (!node) {
      return res.status(404).json({ error: "Node not found" });
    }

    const result = await callNodeFiles(node, {
      action,
      server: serverRecord,
      path: req.body.path || ".",
      contentBase64: req.body.contentBase64,
      encoding: req.body.encoding || "utf8",
    });

    res.json(result);
  } catch (error) {
    const statusCode = Number(error.statusCode) || 502;
    res.status(statusCode).json({ error: error.message });
  }
}

app.post("/api/servers/:uuid/files/list", attachUser, async (req, res) => {
  return forwardFileAction(req, res, "list");
});

app.post("/api/servers/:uuid/files/mkdir", attachUser, async (req, res) => {
  return forwardFileAction(req, res, "mkdir");
});

app.post("/api/servers/:uuid/files/upload", attachUser, async (req, res) => {
  if (!req.body.path || !req.body.contentBase64) {
    return res.status(400).json({ error: "path and contentBase64 are required" });
  }
  return forwardFileAction(req, res, "upload");
});

app.post("/api/servers/:uuid/files/delete", attachUser, async (req, res) => {
  return forwardFileAction(req, res, "delete");
});

app.post("/api/servers/:uuid/files/download", attachUser, async (req, res) => {
  return forwardFileAction(req, res, "download");
});

app.get("/api/servers/:uuid/backups", attachUser, async (req, res) => {
  const { uuid } = req.params;
  try {
    const serverRecord = await resolveServer(uuid);
    assertServerAccess(req.user, serverRecord);
    const node = await resolveNode(serverRecord.nodeId);
    if (!node) {
      return res.status(404).json({ error: "Node not found" });
    }
    const result = await callNodeEndpoint(node, "/server/backups/list", { uuid });
    res.json(result);
  } catch (error) {
    const statusCode = Number(error.statusCode) || 502;
    res.status(statusCode).json({ error: error.message });
  }
});

app.post("/api/servers/:uuid/backups/create", attachUser, async (req, res) => {
  const { uuid } = req.params;
  try {
    const serverRecord = await resolveServer(uuid);
    assertServerAccess(req.user, serverRecord);
    const node = await resolveNode(serverRecord.nodeId);
    if (!node) {
      return res.status(404).json({ error: "Node not found" });
    }
    const result = await callNodeEndpoint(node, "/server/backups/create", {
      uuid,
      label: req.body?.label,
    });
    res.json(result);
  } catch (error) {
    const statusCode = Number(error.statusCode) || 502;
    res.status(statusCode).json({ error: error.message });
  }
});

app.post("/api/servers/:uuid/backups/delete", attachUser, async (req, res) => {
  const { uuid } = req.params;
  try {
    const serverRecord = await resolveServer(uuid);
    assertServerAccess(req.user, serverRecord);
    const node = await resolveNode(serverRecord.nodeId);
    if (!node) {
      return res.status(404).json({ error: "Node not found" });
    }
    const name = String(req.body?.name || "").trim();
    if (!name) {
      return res.status(400).json({ error: "name is required" });
    }
    const result = await callNodeEndpoint(node, "/server/backups/delete", { uuid, name });
    res.json(result);
  } catch (error) {
    const statusCode = Number(error.statusCode) || 502;
    res.status(statusCode).json({ error: error.message });
  }
});

app.post("/api/servers/:uuid/backups/download", attachUser, async (req, res) => {
  const { uuid } = req.params;
  try {
    const serverRecord = await resolveServer(uuid);
    assertServerAccess(req.user, serverRecord);
    const node = await resolveNode(serverRecord.nodeId);
    if (!node) {
      return res.status(404).json({ error: "Node not found" });
    }
    const name = String(req.body?.name || "").trim();
    if (!name) {
      return res.status(400).json({ error: "name is required" });
    }
    const result = await callNodeEndpoint(node, "/server/backups/download", { uuid, name });
    res.json(result);
  } catch (error) {
    const statusCode = Number(error.statusCode) || 502;
    res.status(statusCode).json({ error: error.message });
  }
});

app.get("/api/v1/servers", requireApiKey(["servers"]), async (req, res) => {
  const servers = await readJson(serversFile, []);
  res.json({ servers, api_key_owner: req.apiKey.owner });
});

app.get("/api/v1/servers/:uuid", requireApiKey(["servers"]), async (req, res) => {
  const server = await resolveServer(req.params.uuid);
  if (!server) {
    return res.status(404).json({ error: "Server not found" });
  }
  res.json({ server });
});

app.post("/api/v1/servers/:uuid/actions/:action", requireApiKey(["servers"]), async (req, res) => {
  const { uuid, action } = req.params;
  const actionMap = {
    start: "start_server",
    stop: "stop_server",
    restart: "restart_server",
    kill: "kill_server",
  };

  const mapped = actionMap[action];
  if (!mapped) {
    return res.status(400).json({ error: "Unsupported action" });
  }

  try {
    const { result, targetServer } = await callServerNodeWithApiKey(uuid, {
      action: mapped,
    });

    const statusMap = {
      start: "starting",
      stop: "stopping",
      restart: "restarting",
      kill: "stopping",
    };

    await setServerStatus(uuid, statusMap[action] || "unknown");

    await appendAuditLog({
      type: `api_key.server.${action}`,
      actorId: req.apiKey.id,
      actorEmail: req.apiKey.owner,
      serverUuid: uuid,
      nodeId: targetServer.nodeId,
    });

    res.json({ ok: true, result });
  } catch (error) {
    const statusCode = Number(error.statusCode) || 502;
    res.status(statusCode).json({ error: error.message });
  }
});

app.get("/api/v1/nodes", requireApiKey(["nodes"]), async (_req, res) => {
  const nodes = await readJson(nodesFile, []);
  res.json({ nodes: nodes.map(sanitizeNode) });
});

app.get("/api/v1/users", requireApiKey(["users"]), async (_req, res) => {
  const users = await readJson(usersFile, []);
  res.json({ users: users.map(sanitizeUser) });
});

app.get("/api/v1/panel/settings", requireApiKey(["panel"]), async (_req, res) => {
  const [settings, themes] = await Promise.all([readPanelSettings(), readThemes()]);
  res.json({ settings, themes });
});

app.get("/api/admin/users", attachUser, requireAdmin, async (_req, res) => {
  const [users, servers] = await Promise.all([
    readJson(usersFile, []),
    readJson(serversFile, []),
  ]);

  const serverCountByUser = new Map();
  for (const item of servers) {
    serverCountByUser.set(item.createdBy, (serverCountByUser.get(item.createdBy) || 0) + 1);
  }

  res.json({
    users: users.map((user) => ({
      ...sanitizeUser(user),
      server_count: serverCountByUser.get(user.id) || 0,
    })),
  });
});

app.post("/api/admin/users", attachUser, requireAdmin, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const email = String(req.body?.email || "").toLowerCase().trim();
  const password = String(req.body?.password || "");
  const role = req.body?.role === "admin" ? "admin" : "user";

  if (!name || !email || !password) {
    return res.status(400).json({ error: "name, email, password are required" });
  }

  const [settings, themes] = await Promise.all([readPanelSettings(), readThemes()]);
  const serverLimit = normalizeServerLimit(
    req.body?.server_limit,
    settings.default_server_limit
  );
  const theme = normalizeThemeId(req.body?.theme, themes, settings.default_theme);

  let createdUser;
  try {
    await updateJson(usersFile, [], (users) => {
      if (users.some((item) => item.email.toLowerCase() === email)) {
        throw new Error("Email already exists");
      }

      createdUser = {
        id: crypto.randomUUID(),
        name,
        email,
        role,
        passwordHash: hashPassword(password),
        server_limit: serverLimit,
        theme,
        createdAt: nowIso(),
      };

      users.push(createdUser);
      return users;
    });
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }

  await appendAuditLog({
    type: "admin.user.create",
    actorId: req.user.id,
    actorEmail: req.user.email,
    targetUserId: createdUser.id,
    targetEmail: createdUser.email,
  });

  res.status(201).json({ user: sanitizeUser(createdUser) });
});

app.patch("/api/admin/users/:id", attachUser, requireAdmin, async (req, res) => {
  const targetId = req.params.id;

  const payload = {};
  if (req.body?.name !== undefined) {
    const name = String(req.body.name).trim();
    if (!name) {
      return res.status(400).json({ error: "name cannot be empty" });
    }
    payload.name = name;
  }

  if (req.body?.role !== undefined) {
    if (!["admin", "user"].includes(req.body.role)) {
      return res.status(400).json({ error: "role must be admin or user" });
    }
    payload.role = req.body.role;
  }

  if (req.body?.server_limit !== undefined) {
    payload.server_limit = normalizeServerLimit(req.body.server_limit, NaN);
    if (!Number.isFinite(payload.server_limit)) {
      return res.status(400).json({ error: "server_limit must be a number (or -1)" });
    }
  }

  if (req.body?.theme !== undefined) {
    const themes = await readThemes();
    const theme = normalizeThemeId(req.body.theme, themes, "");
    if (!theme) {
      return res.status(400).json({ error: "Unknown theme" });
    }
    payload.theme = theme;
  }

  if (Object.keys(payload).length === 0) {
    return res.status(400).json({ error: "No valid fields to update" });
  }

  let updated = null;
  await updateJson(usersFile, [], (users) => {
    return users.map((user) => {
      if (user.id !== targetId) {
        return user;
      }
      updated = {
        ...user,
        ...payload,
      };
      return updated;
    });
  });

  if (!updated) {
    return res.status(404).json({ error: "User not found" });
  }

  await appendAuditLog({
    type: "admin.user.update",
    actorId: req.user.id,
    actorEmail: req.user.email,
    targetUserId: updated.id,
    updates: payload,
  });

  res.json({ user: sanitizeUser(updated) });
});

app.delete("/api/admin/users/:id", attachUser, requireAdmin, async (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: "Cannot delete your own account" });
  }

  let removed = null;
  await updateJson(usersFile, [], (users) => {
    const index = users.findIndex((item) => item.id === req.params.id);
    if (index < 0) {
      return users;
    }

    removed = users[index];
    users.splice(index, 1);
    return users;
  });

  if (!removed) {
    return res.status(404).json({ error: "User not found" });
  }

  await updateJson(sessionsFile, [], (sessions) => sessions.filter((item) => item.userId !== removed.id));

  await appendAuditLog({
    type: "admin.user.delete",
    actorId: req.user.id,
    actorEmail: req.user.email,
    targetUserId: removed.id,
    targetEmail: removed.email,
  });

  res.json({ ok: true });
});

app.get("/api/admin/panel-settings", attachUser, requireAdmin, async (_req, res) => {
  const [settings, themes] = await Promise.all([readPanelSettings(), readThemes()]);
  res.json({ settings, themes });
});

app.put("/api/admin/panel-settings", attachUser, requireAdmin, async (req, res) => {
  const body = req.body || {};
  const patch = {};

  if (body.default_theme !== undefined) {
    const themes = await readThemes();
    const theme = normalizeThemeId(body.default_theme, themes, "");
    if (!theme) {
      return res.status(400).json({ error: "Unknown default_theme" });
    }
    patch.default_theme = theme;
  }

  if (body.button_color !== undefined) {
    if (!isHexColor(body.button_color)) {
      return res.status(400).json({ error: "button_color must be a hex color (#RRGGBB)" });
    }
    patch.button_color = String(body.button_color);
  }

  if (body.sidebar_color !== undefined) {
    if (!isHexColor(body.sidebar_color)) {
      return res.status(400).json({ error: "sidebar_color must be a hex color (#RRGGBB)" });
    }
    patch.sidebar_color = String(body.sidebar_color);
  }

  if (body.card_color !== undefined) {
    if (!isHexColor(body.card_color)) {
      return res.status(400).json({ error: "card_color must be a hex color (#RRGGBB)" });
    }
    patch.card_color = String(body.card_color);
  }

  if (body.background_image !== undefined) {
    const value = String(body.background_image || "").trim();
    if (value && !isValidUrl(value)) {
      return res.status(400).json({ error: "background_image must be a valid URL (http/https) or empty" });
    }
    patch.background_image = value;
  }

  if (body.default_server_limit !== undefined) {
    const limit = normalizeServerLimit(body.default_server_limit, NaN);
    if (!Number.isFinite(limit)) {
      return res
        .status(400)
        .json({ error: "default_server_limit must be a number (or -1)" });
    }
    patch.default_server_limit = limit;
  }

  if (Object.keys(patch).length === 0) {
    return res.status(400).json({ error: "No valid settings fields provided" });
  }

  const settings = await updateJson(panelSettingsFile, DEFAULT_PANEL_SETTINGS, (current) => {
    return toThemePayload({
      ...current,
      ...patch,
    });
  });

  if (patch.default_theme) {
    await updateJson(usersFile, [], (users) =>
      users.map((user) => ({
        ...user,
        theme: patch.default_theme,
      }))
    );
  }

  await appendAuditLog({
    type: "admin.settings.update",
    actorId: req.user.id,
    actorEmail: req.user.email,
    updates: patch,
  });

  res.json({ settings });
});

app.get("/api/admin/themes", attachUser, requireAdmin, async (_req, res) => {
  const themes = await readThemes();
  res.json({ themes });
});

app.post("/api/admin/themes", attachUser, requireAdmin, async (req, res) => {
  const fallbackPalette = DEFAULT_THEMES[0].palette;
  const candidate = sanitizeThemeRecord(
    {
      id: req.body?.id,
      name: req.body?.name,
      palette: req.body?.palette || req.body,
      locked: false,
    },
    fallbackPalette
  );

  if (!candidate) {
    return res.status(400).json({ error: "Invalid theme payload" });
  }

  let duplicate = false;
  await updateJson(themesFile, DEFAULT_THEMES, (themes) => {
    const list = Array.isArray(themes) ? themes : [];
    if (list.some((theme) => theme.id === candidate.id)) {
      duplicate = true;
      return list;
    }
    list.push({ ...candidate, locked: false });
    return list;
  });

  if (duplicate) {
    return res.status(409).json({ error: "Theme id already exists" });
  }

  await appendAuditLog({
    type: "admin.theme.create",
    actorId: req.user.id,
    actorEmail: req.user.email,
    themeId: candidate.id,
  });

  res.status(201).json({ theme: candidate });
});

app.put("/api/admin/themes/:id", attachUser, requireAdmin, async (req, res) => {
  const themeId = String(req.params.id || "").toLowerCase();
  const themes = await readThemes();
  const existing = resolveThemeById(themes, themeId);
  if (!existing) {
    return res.status(404).json({ error: "Theme not found" });
  }

  const paletteUpdates = extractPaletteUpdates(req.body);
  const next = sanitizeThemeRecord(
    {
      id: themeId,
      name: req.body?.name ?? existing.name,
      palette: { ...existing.palette, ...paletteUpdates },
      locked: existing.locked,
    },
    DEFAULT_THEMES[0].palette
  );

  if (!next) {
    return res.status(400).json({ error: "Invalid theme payload" });
  }

  await updateJson(themesFile, DEFAULT_THEMES, (list) => {
    const themesList = Array.isArray(list) ? list : [];
    return themesList.map((theme) => (theme.id === themeId ? next : theme));
  });

  await appendAuditLog({
    type: "admin.theme.update",
    actorId: req.user.id,
    actorEmail: req.user.email,
    themeId,
  });

  res.json({ theme: next });
});

app.delete("/api/admin/themes/:id", attachUser, requireAdmin, async (req, res) => {
  const themeId = String(req.params.id || "").toLowerCase();
  let removed = null;

  await updateJson(themesFile, DEFAULT_THEMES, (list) => {
    const themes = Array.isArray(list) ? list : [];
    const index = themes.findIndex((theme) => theme.id === themeId);
    if (index < 0) {
      return themes;
    }
    if (themes[index].locked) {
      removed = { locked: true };
      return themes;
    }
    removed = themes[index];
    themes.splice(index, 1);
    return themes;
  });

  if (!removed) {
    return res.status(404).json({ error: "Theme not found" });
  }
  if (removed.locked) {
    return res.status(400).json({ error: "Cannot delete built-in themes" });
  }

  await appendAuditLog({
    type: "admin.theme.delete",
    actorId: req.user.id,
    actorEmail: req.user.email,
    themeId,
  });

  res.json({ ok: true });
});

app.get("/api/admin/nodes", attachUser, requireAdmin, async (_req, res) => {
  const nodes = await readJson(nodesFile, []);
  res.json({
    nodes: nodes.map((node) => ({
      ...sanitizeNode(node),
      secretMasked: node.secret ? "********" : "",
      tokenMasked: node.token ? "********" : "",
      panelSecretMasked: node.panelSecret ? "********" : "",
      agentSecretMasked: node.agentSecret ? "********" : "",
    })),
  });
});

app.post("/api/admin/nodes", attachUser, requireAdmin, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const url = String(req.body?.url || "").trim();
  const secret = String(req.body?.secret || "").trim();
  const token = String(req.body?.token || "").trim() || secret;
  const panelSecret = String(req.body?.panelSecret || "").trim() || secret;
  const agentSecret = String(req.body?.agentSecret || "").trim() || secret;
  const protocol = String(req.body?.protocol || "signed").trim().toLowerCase();
  const idInput = String(req.body?.id || "").trim();

  if (!name || !url || !secret) {
    return res.status(400).json({ error: "name, url, and secret are required" });
  }

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return res.status(400).json({ error: "url must be a valid URL" });
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return res.status(400).json({ error: "url must use http or https" });
  }

  if (!["signed", "legacy"].includes(protocol)) {
    return res.status(400).json({ error: "protocol must be signed or legacy" });
  }

  const nodeRecord = {
    id: idInput || `node-${crypto.randomUUID().slice(0, 8)}`,
    name,
    url: parsed.toString().replace(/\/$/, ""),
    secret,
    token,
    panelSecret,
    agentSecret,
    protocol,
    status: "offline",
    lastHeartbeat: null,
    resources: {},
  };

  let duplicate = false;
  await updateJson(nodesFile, [], (nodes) => {
    if (nodes.some((node) => node.id === nodeRecord.id)) {
      duplicate = true;
      return nodes;
    }
    nodes.push(nodeRecord);
    return nodes;
  });

  if (duplicate) {
    return res.status(409).json({ error: "Node id already exists" });
  }

  await appendAuditLog({
    type: "admin.node.create",
    actorId: req.user.id,
    actorEmail: req.user.email,
    nodeId: nodeRecord.id,
  });

  res.status(201).json({ node: sanitizeNode(nodeRecord) });
});

app.delete("/api/admin/nodes/:id", attachUser, requireAdmin, async (req, res) => {
  const nodeId = req.params.id;
  const servers = await readJson(serversFile, []);
  const assignedCount = servers.filter((item) => item.nodeId === nodeId).length;
  if (assignedCount > 0) {
    return res.status(400).json({
      error: `Cannot remove node while ${assignedCount} server(s) are assigned to it`,
    });
  }

  let removed = null;
  await updateJson(nodesFile, [], (nodes) => {
    const index = nodes.findIndex((node) => node.id === nodeId);
    if (index < 0) {
      return nodes;
    }
    removed = nodes[index];
    nodes.splice(index, 1);
    return nodes;
  });

  if (!removed) {
    return res.status(404).json({ error: "Node not found" });
  }

  await appendAuditLog({
    type: "admin.node.delete",
    actorId: req.user.id,
    actorEmail: req.user.email,
    nodeId,
  });

  res.json({ ok: true });
});

app.get("/api/admin/logs", attachUser, requireAdmin, async (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit || 200), 2000));
  const logs = await readJson(logsFile, []);
  res.json({
    logs: logs.slice(-limit).reverse(),
  });
});

app.get("/api/admin/audit-logs", attachUser, requireAdmin, async (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit || 200), 2000));
  const logs = await readJson(logsFile, []);
  const filtered = logs.filter(
    (entry) =>
      !String(entry.type || "").startsWith("server.") &&
      !String(entry.type || "").startsWith("console.")
  );
  res.json({ logs: filtered.slice(-limit).reverse() });
});

app.get("/api/admin/user-logs", attachUser, requireAdmin, async (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit || 200), 2000));
  const logs = await readJson(logsFile, []);
  const filtered = logs.filter(
    (entry) =>
      String(entry.type || "").startsWith("server.") ||
      String(entry.type || "").startsWith("console.")
  );
  res.json({ logs: filtered.slice(-limit).reverse() });
});

app.get("/api/admin/api-keys", attachUser, requireAdmin, async (_req, res) => {
  const keys = await readJson(apiKeysFile, []);
  res.json({
    api_keys: (Array.isArray(keys) ? keys : []).map((item) => ({
      id: item.id,
      owner: item.owner,
      permissions: item.permissions || [],
      created_at: item.created_at,
      key_masked: maskApiKey(item.key),
    })),
  });
});

app.post("/api/admin/api-keys", attachUser, requireAdmin, async (req, res) => {
  const owner = String(req.body?.owner || req.user.email || "").trim();
  const permissions = normalizePermissions(req.body?.permissions);
  if (!owner) {
    return res.status(400).json({ error: "owner is required" });
  }
  if (permissions.length === 0) {
    return res.status(400).json({ error: "permissions are required" });
  }

  const record = {
    id: crypto.randomUUID(),
    key: generateApiKey(),
    owner,
    permissions,
    created_at: nowIso(),
  };

  await updateJson(apiKeysFile, [], (keys) => {
    const list = Array.isArray(keys) ? keys : [];
    list.push(record);
    return list;
  });

  await appendAuditLog({
    type: "admin.api_key.create",
    actorId: req.user.id,
    actorEmail: req.user.email,
    owner,
    permissions,
  });

  res.status(201).json({ api_key: record });
});

app.delete("/api/admin/api-keys/:id", attachUser, requireAdmin, async (req, res) => {
  const keyId = req.params.id;
  let removed = null;

  await updateJson(apiKeysFile, [], (keys) => {
    const list = Array.isArray(keys) ? keys : [];
    const index = list.findIndex((item) => item.id === keyId);
    if (index < 0) {
      return list;
    }
    removed = list[index];
    list.splice(index, 1);
    return list;
  });

  if (!removed) {
    return res.status(404).json({ error: "API key not found" });
  }

  await appendAuditLog({
    type: "admin.api_key.delete",
    actorId: req.user.id,
    actorEmail: req.user.email,
    apiKeyId: removed.id,
    owner: removed.owner,
  });

  res.json({ ok: true });
});

app.get("/api/admin/update/status", attachUser, requireAdmin, async (_req, res) => {
  const [state] = await Promise.all([readUpdateState()]);
  res.json({
    local_version: getLocalVersion(),
    state,
  });
});

app.post("/api/admin/update/check", attachUser, requireAdmin, async (req, res) => {
  const current = await readUpdateState();
  const url = String(req.body?.url || current.source_url || DEFAULT_UPDATE_STATE.source_url).trim();
  try {
    const remoteVersion = await fetchRemoteVersion(url);
    const localVersion = getLocalVersion();
    const updateAvailable =
      compareVersions(parseVersion(remoteVersion), parseVersion(localVersion)) > 0;

    const next = await writeUpdateState({
      source_url: url,
      remote_version: remoteVersion,
      checked_at: nowIso(),
      update_available: updateAvailable,
      last_error: null,
    });

    res.json({ local_version: localVersion, state: next });
  } catch (error) {
    const next = await writeUpdateState({
      source_url: url,
      checked_at: nowIso(),
      last_error: error.message,
    });
    res.status(502).json({ error: error.message, state: next });
  }
});

app.post("/api/admin/update/apply", attachUser, requireAdmin, async (req, res) => {
  const panelDir = baseDir;
  const wingsDir = path.join(baseDir, "..", "NodeDash-Wings");
  const results = [];
  let failed = false;

  try {
    const panelResult = await runGitUpdate(panelDir);
    results.push({ target: "panel", ...panelResult });
    if (!panelResult.ok && !panelResult.skipped) {
      failed = true;
    }
  } catch (error) {
    results.push({
      target: "panel",
      ok: false,
      error: error.message || "Panel update failed",
      output: `${error.stdout || ""}${error.stderr || ""}`.trim(),
    });
    failed = true;
  }

  if (fs.existsSync(wingsDir)) {
    try {
      const wingsResult = await runGitUpdate(wingsDir);
      results.push({ target: "wings", ...wingsResult });
      if (!wingsResult.ok && !wingsResult.skipped) {
        failed = true;
      }
    } catch (error) {
      results.push({
        target: "wings",
        ok: false,
        error: error.message || "Wings update failed",
        output: `${error.stdout || ""}${error.stderr || ""}`.trim(),
      });
      failed = true;
    }
  } else {
    results.push({ target: "wings", ok: false, skipped: true, reason: "Wings directory not found" });
  }

  await writeUpdateState({
    last_update_at: nowIso(),
    last_update_log: results,
    last_error: failed ? "Update failed" : null,
  });

  await appendAuditLog({
    type: "admin.update.apply",
    actorId: req.user.id,
    actorEmail: req.user.email,
    results,
  });

  if (failed) {
    return res.status(500).json({ ok: false, results });
  }
  res.json({ ok: true, results });
});

app.post("/api/internal/heartbeat", async (req, res) => {
  const node = await verifyInternalNode(req);
  if (!node) {
    return res.status(401).json({ error: "Unauthorized node" });
  }

  const payload = req.body && typeof req.body === "object" ? req.body : {};
  const ts = typeof payload.ts === "string" ? payload.ts : nowIso();
  const resources = payload.resources && typeof payload.resources === "object" ? payload.resources : {};

  await updateJson(nodesFile, [], (nodes) => {
    return nodes.map((item) => {
      if (item.id !== node.id) {
        return item;
      }
      return {
        ...item,
        name: payload.name ? String(payload.name) : item.name,
        ip: payload.ip ? String(payload.ip) : item.ip,
        status: "online",
        lastHeartbeat: ts,
        resources,
      };
    });
  });

  const incomingStats = Array.isArray(payload.servers) ? payload.servers : [];
  if (incomingStats.length > 0) {
    const byUuid = new Map();
    for (const stat of incomingStats) {
      if (stat && stat.uuid) {
        byUuid.set(String(stat.uuid), stat);
      }
    }

    await updateJson(serversFile, [], (servers) => {
      return servers.map((serverItem) => {
        const stat = byUuid.get(serverItem.uuid);
        if (!stat) {
          return serverItem;
        }

        return {
          ...serverItem,
          status: stat.status ? String(stat.status) : serverItem.status,
          pid: stat.pid ?? null,
          updatedAt: ts,
          resources: {
            cpuPercent: Number(stat.cpuPercent || 0),
            ramMb: Number(stat.ramMb || 0),
          },
        };
      });
    });

    for (const stat of byUuid.values()) {
      const uuid = String(stat.uuid);
      const statusEvent = {
        type: "status",
        payload: {
          status: stat.status || "unknown",
          pid: stat.pid ?? null,
        },
        ts,
      };
      const resourceEvent = {
        type: "resource",
        payload: {
          status: stat.status || "unknown",
          pid: stat.pid ?? null,
          cpuPercent: Number(stat.cpuPercent || 0),
          ramMb: Number(stat.ramMb || 0),
        },
        ts,
      };
      pushServerEvent(uuid, statusEvent);
      pushServerEvent(uuid, resourceEvent);
      wsHub.broadcastServerEvent(uuid, statusEvent);
      wsHub.broadcastServerEvent(uuid, resourceEvent);
    }
  }

  wsHub.broadcastNodeEvent({
    nodeId: node.id,
    status: "online",
    resources,
    ts,
  });

  res.json({ ok: true });
});

app.post("/api/internal/events", async (req, res) => {
  const node = await verifyInternalNode(req);
  if (!node) {
    return res.status(401).json({ error: "Unauthorized node" });
  }

  const payload = req.body && typeof req.body === "object" ? req.body : {};
  const uuid = String(payload.uuid || "").trim();
  const type = String(payload.type || "").trim();
  const eventPayload =
    payload.payload && typeof payload.payload === "object" ? payload.payload : {};
  const ts = typeof payload.ts === "string" ? payload.ts : nowIso();

  if (!uuid || !type) {
    return res.status(400).json({ error: "uuid and type are required" });
  }

  const event = {
    type,
    payload: eventPayload,
    ts,
    nodeId: node.id,
  };

  pushServerEvent(uuid, event);
  wsHub.broadcastServerEvent(uuid, event);

  if (type === "status") {
    await updateJson(serversFile, [], (servers) =>
      servers.map((item) => {
        if (item.uuid !== uuid) {
          return item;
        }
        return {
          ...item,
          status: eventPayload.status ? String(eventPayload.status) : item.status,
          lastExit: eventPayload.lastExit || item.lastExit || null,
          updatedAt: ts,
        };
      })
    );
  }

  if (type === "resource") {
    await updateJson(serversFile, [], (servers) =>
      servers.map((item) => {
        if (item.uuid !== uuid) {
          return item;
        }
        return {
          ...item,
          status: eventPayload.status ? String(eventPayload.status) : item.status,
          resources: {
            cpuPercent: Number(eventPayload.cpuPercent || 0),
            ramMb: Number(eventPayload.ramMb || 0),
          },
          pid: eventPayload.pid ?? item.pid ?? null,
          updatedAt: ts,
        };
      })
    );
  }

  if (type === "log" && eventPayload.line !== undefined) {
    await appendAuditLog({
      type: "console.log",
      serverUuid: uuid,
      message: String(eventPayload.line || ""),
    });
  }

  res.json({ ok: true });
});

app.post("/api/internal/node/auth", async (req, res) => {
  const token = String(req.headers.authorization || "").replace("Bearer ", "").trim();
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const nodeId = String(body.node_id || body.nodeId || "").trim();
  if (!nodeId || !token) {
    return res.status(401).json({ error: "Unauthorized node" });
  }

  const nodes = await readJson(nodesFile, []);
  const node = nodes.find((item) => item.id === nodeId);
  if (!node) {
    return res.status(401).json({ error: "Unauthorized node" });
  }

  const expected = node.token || node.secret;
  if (!expected || token !== expected) {
    return res.status(401).json({ error: "Unauthorized node" });
  }

  const system = body.system && typeof body.system === "object" ? body.system : {};
  const publicKey = String(body.public_key || "").trim();
  const ts = nowIso();

  await updateJson(nodesFile, [], (items) =>
    items.map((item) => {
      if (item.id !== nodeId) return item;
      return {
        ...item,
        status: "online",
        lastHeartbeat: ts,
        system: {
          cpu: Number(system.cpu || 0),
          ram: Number(system.ram || 0),
          disk: Number(system.disk || 0),
        },
        publicKey: publicKey || item.publicKey || null,
      };
    })
  );

  wsHub.broadcastNodeEvent({
    nodeId,
    status: "online",
    system,
    ts,
  });

  res.json({ ok: true, panel_public_key: readPanelPublicKey() });
});

app.post("/api/internal/node/heartbeat", async (req, res) => {
  const node = await verifySignedNodeRequest(req);
  if (!node) {
    return res.status(401).json({ error: "Unauthorized node" });
  }

  const payload = req.body && typeof req.body === "object" ? req.body : {};
  const ts = nowIso();
  const cpuUsage = Number(payload.cpu_usage || payload.cpuUsage || 0);
  const ramUsage = Number(payload.ram_usage || payload.ramUsage || 0);
  const diskUsage = Number(payload.disk_usage || payload.diskUsage || 0);
  const system = node.system || {};
  const ramTotal = Number(system.ram || 0);
  const diskTotal = Number(system.disk || 0);
  const resources = {
    cpuPercent: cpuUsage,
    ramUsedMb: ramUsage,
    ramTotalMb: ramTotal,
    ramUsedPercent: ramTotal ? (ramUsage / ramTotal) * 100 : 0,
    diskUsedMb: diskUsage,
    diskTotalMb: diskTotal,
    diskUsedPercent: diskTotal ? (diskUsage / diskTotal) * 100 : 0,
  };

  await updateJson(nodesFile, [], (nodes) =>
    nodes.map((item) => {
      if (item.id !== node.id) return item;
      return {
        ...item,
        status: "online",
        lastHeartbeat: ts,
        resources,
      };
    })
  );

  wsHub.broadcastNodeEvent({
    nodeId: node.id,
    status: "online",
    resources,
    ts,
  });

  res.json({ ok: true });
});

app.post("/api/internal/node/events", async (req, res) => {
  const node = await verifySignedNodeRequest(req);
  if (!node) {
    return res.status(401).json({ error: "Unauthorized node" });
  }

  const payload = req.body && typeof req.body === "object" ? req.body : {};
  const events = Array.isArray(payload.events) ? payload.events : [];
  const now = nowIso();
  const resourceUpdates = new Map();

  for (const item of events) {
    if (!item) continue;
    const uuid = String(item.serverUuid || item.uuid || "").trim();
    if (!uuid) continue;

    if (item.type === "status") {
      const statusValue = item.status || item.payload?.status || "unknown";
      const statusEvent = {
        type: "status",
        payload: { status: statusValue },
        ts: now,
        nodeId: node.id,
      };
      pushServerEvent(uuid, statusEvent);
      wsHub.broadcastServerEvent(uuid, statusEvent);
      await updateJson(serversFile, [], (servers) =>
        servers.map((serverItem) =>
          serverItem.uuid === uuid
            ? { ...serverItem, status: statusValue, updatedAt: now }
            : serverItem
        )
      );
      continue;
    }

    if (item.type === "log" || item.line !== undefined) {
      const line = item.line !== undefined ? item.line : item.payload?.line;
      const logEvent = {
        type: "log",
        payload: { line: String(line || "") },
        ts: now,
        nodeId: node.id,
      };
      pushServerEvent(uuid, logEvent);
      wsHub.broadcastServerEvent(uuid, logEvent);
      await appendAuditLog({
        type: "console.log",
        serverUuid: uuid,
        message: String(line || ""),
      });
      continue;
    }

    if (item.metrics) {
      const metrics = item.metrics || {};
      const resourcePayload = {
        cpuPercent: Number(metrics.cpu_percent || metrics.cpuPercent || 0),
        ramMb: Number(metrics.ram_mb || metrics.ramMb || 0),
        diskMb: Number(metrics.disk_mb || metrics.diskMb || 0),
        netRxKb: Number(metrics.net_rx_kb || metrics.netRxKb || 0),
        netTxKb: Number(metrics.net_tx_kb || metrics.netTxKb || 0),
        diskReadKb: Number(metrics.disk_read_kb || metrics.diskReadKb || 0),
        diskWriteKb: Number(metrics.disk_write_kb || metrics.diskWriteKb || 0),
        raw: metrics.raw,
      };
      const resourceEvent = {
        type: "resource",
        payload: resourcePayload,
        ts: now,
        nodeId: node.id,
      };
      pushServerEvent(uuid, resourceEvent);
      wsHub.broadcastServerEvent(uuid, resourceEvent);
      resourceUpdates.set(uuid, resourcePayload);
    }
  }

  if (resourceUpdates.size > 0) {
    await updateJson(serversFile, [], (servers) =>
      servers.map((item) => {
        const resourcePayload = resourceUpdates.get(item.uuid);
        if (!resourcePayload) return item;
        return {
          ...item,
          resources: {
            cpuPercent: Number(resourcePayload.cpuPercent || 0),
            ramMb: Number(resourcePayload.ramMb || 0),
            diskMb: Number(resourcePayload.diskMb || 0),
            netRxKb: Number(resourcePayload.netRxKb || 0),
            netTxKb: Number(resourcePayload.netTxKb || 0),
          },
          updatedAt: now,
        };
      })
    );
  }

  res.json({ ok: true });
});

app.get("/", (_req, res) => {
  res.redirect("/dashboard");
});

app.get("/login", (_req, res) => {
  res.sendFile(path.join(publicDir, "login.html"));
});

app.get("/dashboard", (_req, res) => {
  res.sendFile(path.join(publicDir, "dashboard.html"));
});

app.get("/nodes", (_req, res) => {
  res.sendFile(path.join(publicDir, "nodes.html"));
});

app.get("/servers", (_req, res) => {
  res.sendFile(path.join(publicDir, "servers.html"));
});

app.get("/servers/create", (_req, res) => {
  res.sendFile(path.join(publicDir, "create-server.html"));
});

app.get("/servers/:uuid", (_req, res) => {
  res.sendFile(path.join(publicDir, "server.html"));
});

app.get("/servers/:uuid/console", (_req, res) => {
  res.sendFile(path.join(publicDir, "console.html"));
});

app.get("/servers/:uuid/files", (_req, res) => {
  res.sendFile(path.join(publicDir, "files.html"));
});

app.get("/servers/:uuid/resources", (_req, res) => {
  res.sendFile(path.join(publicDir, "resources.html"));
});

app.get("/servers/:uuid/settings", (_req, res) => {
  res.sendFile(path.join(publicDir, "server-settings.html"));
});

app.get("/settings", (_req, res) => {
  res.sendFile(path.join(publicDir, "settings.html"));
});

app.get("/forbidden", (_req, res) => {
  sendForbiddenPage(res);
});

app.get("/admin", requireAdminPage, (_req, res) => {
  res.sendFile(path.join(publicDir, "admin.html"));
});

app.get("/admin/users", requireAdminPage, (_req, res) => {
  res.sendFile(path.join(publicDir, "admin-users.html"));
});

app.get("/admin/nodes", requireAdminPage, (_req, res) => {
  res.sendFile(path.join(publicDir, "admin-nodes.html"));
});

app.get("/admin/api-keys", requireAdminPage, (_req, res) => {
  res.sendFile(path.join(publicDir, "admin-api-keys.html"));
});

app.get("/admin/audit-logs", requireAdminPage, (_req, res) => {
  res.sendFile(path.join(publicDir, "admin-audit-logs.html"));
});

app.get("/admin/user-logs", requireAdminPage, (_req, res) => {
  res.sendFile(path.join(publicDir, "admin-user-logs.html"));
});

app.get("/admin/themes", requireAdminPage, (_req, res) => {
  res.sendFile(path.join(publicDir, "admin-themes.html"));
});

app.get("/admin/update", requireAdminPage, (_req, res) => {
  res.sendFile(path.join(publicDir, "admin-update.html"));
});

app.get("/admin/docker", requireAdminPage, (_req, res) => {
  res.sendFile(path.join(publicDir, "admin-docker.html"));
});

app.use("/api", (_req, res) => {
  res.status(404).json({ error: "Not found" });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  if (res.headersSent) {
    return;
  }
  res.status(500).json({ error: "Internal server error" });
});

function startNodeOfflineWatcher() {
  const offlineAfterMs = Math.max(
    10000,
    Number(process.env.NODE_OFFLINE_AFTER_MS || 15000)
  );

  setInterval(() => {
    updateJson(nodesFile, [], (nodes) => {
      const now = Date.now();
      return nodes.map((node) => {
        const last = node.lastHeartbeat ? new Date(node.lastHeartbeat).getTime() : 0;
        const shouldBeOnline = last > 0 && now - last <= offlineAfterMs;
        const nextStatus = shouldBeOnline ? "online" : "offline";
        if (nextStatus !== node.status) {
          wsHub.broadcastNodeEvent({
            nodeId: node.id,
            status: nextStatus,
            ts: nowIso(),
          });
        }
        return {
          ...node,
          status: nextStatus,
        };
      });
    }).catch((error) => {
      console.error("Node liveness watcher error:", error.message);
    });
  }, 5000);
}

async function bootstrapAndStart() {
  await ensureBootstrapData();
  startNodeOfflineWatcher();

  server.listen(PORT, HOST, () => {
    console.log(`[panel] listening on http://${HOST}:${PORT}`);
  });
}

bootstrapAndStart().catch((error) => {
  console.error("[panel] failed to start:", error);
  process.exit(1);
});
