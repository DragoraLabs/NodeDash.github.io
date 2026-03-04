const express = require("express");
const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const { readJson, updateJson } = require("./lib/dataStore");
const { createAuth } = require("./lib/auth");
const { hashPassword, verifyPassword, issueToken, verifyToken } = require("./lib/security");
const { callNodeCommand, callNodeFiles } = require("./lib/wingsClient");
const { createWsHub } = require("./lib/wsHub");

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const TOKEN_TTL_SECONDS = Number(process.env.JWT_TTL_SECONDS || 60 * 60 * 24);

const DEFAULT_PANEL_SETTINGS = {
  default_theme: "gray",
  button_color: "#4a4a4a",
  sidebar_color: "#2f2f2f",
  card_color: "#ffffff",
  default_server_limit: 1,
};

const THEME_SET = new Set(["gray", "light", "dark"]);

const app = express();

const baseDir = __dirname;
const dataDir = path.join(baseDir, "data");
const publicDir = path.join(baseDir, "public");

const usersFile = path.join(dataDir, "users.json");
const sessionsFile = path.join(dataDir, "sessions.json");
const nodesFile = path.join(dataDir, "nodes.json");
const serversFile = path.join(dataDir, "servers.json");
const logsFile = path.join(dataDir, "logs.json");
const panelSettingsFile = path.join(dataDir, "panel_settings.json");

const serverEvents = new Map();

const { attachUser, requireAdmin, sanitizeUser, getBearerToken } = createAuth(dataDir);

function nowIso() {
  return new Date().toISOString();
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

function normalizeTheme(value, fallback = "gray") {
  const candidate = String(value || "").toLowerCase();
  return THEME_SET.has(candidate) ? candidate : fallback;
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

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  return req.socket.remoteAddress || "unknown";
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
  return clone;
}

function sendForbiddenPage(res) {
  res.status(403).sendFile(path.join(publicDir, "403.html"));
}

function toThemePayload(settings) {
  return {
    default_theme: normalizeTheme(settings.default_theme, DEFAULT_PANEL_SETTINGS.default_theme),
    button_color: isHexColor(settings.button_color)
      ? settings.button_color
      : DEFAULT_PANEL_SETTINGS.button_color,
    sidebar_color: isHexColor(settings.sidebar_color)
      ? settings.sidebar_color
      : DEFAULT_PANEL_SETTINGS.sidebar_color,
    card_color: isHexColor(settings.card_color)
      ? settings.card_color
      : DEFAULT_PANEL_SETTINGS.card_color,
    default_server_limit: normalizeServerLimit(
      settings.default_server_limit,
      DEFAULT_PANEL_SETTINGS.default_server_limit
    ),
  };
}

async function readPanelSettings() {
  const settings = await readJson(panelSettingsFile, DEFAULT_PANEL_SETTINGS);
  return toThemePayload(settings);
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
  if (runtime === "node" || runtime === "python") {
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
    errors.push("runtime must be node or python");
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
    entryFile: String(body?.entryFile || (runtime === "node" ? "index.js" : "app.py")).trim(),
    startCommand: body?.startCommand ? String(body.startCommand).trim() : null,
    ramLimitMb,
    cpuLimitPercent,
    autoRestart: body?.autoRestart !== false,
    autoStart: body?.autoStart !== false,
  };
}

function createServerRecord(input, userId) {
  const createdAt = nowIso();
  return {
    uuid: crypto.randomUUID(),
    name: input.name,
    nodeId: input.nodeId,
    runtime: input.runtime,
    entryFile: input.entryFile,
    startCommand: input.startCommand,
    ramLimitMb: Number(input.ramLimitMb),
    cpuLimitPercent: Number(input.cpuLimitPercent),
    autoRestart: input.autoRestart !== false,
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
  const defaultAdminEmail = process.env.DEFAULT_ADMIN_EMAIL || "admin@example.com";
  const defaultAdminPassword = process.env.DEFAULT_ADMIN_PASSWORD || "admin123";

  const settings = await updateJson(panelSettingsFile, DEFAULT_PANEL_SETTINGS, (current) => {
    return {
      ...DEFAULT_PANEL_SETTINGS,
      ...toThemePayload(current),
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
        theme: normalizeTheme(user.theme, settings.default_theme),
        server_limit: normalizeServerLimit(user.server_limit, settings.default_server_limit),
      };
    });
  });

  await updateJson(nodesFile, [], (nodes) => {
    if (nodes.length > 0) {
      return nodes;
    }

    nodes.push({
      id: "node-1",
      name: "Primary Node",
      url: "http://127.0.0.1:8080",
      secret: process.env.DEFAULT_NODE_SECRET || "nodewings-shared-secret",
      status: "offline",
      lastHeartbeat: null,
      resources: {},
    });
    return nodes;
  });

  await updateJson(sessionsFile, [], (sessions) => sessions);
  await updateJson(serversFile, [], (servers) => servers);
  await updateJson(logsFile, [], (logs) => logs);
}

app.disable("x-powered-by");
app.use(express.json({ limit: "12mb" }));
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
app.use(express.static(publicDir));

app.get("/health", (_req, res) => {
  res.json({ status: "ok", ts: nowIso() });
});

app.get("/api/panel-settings", async (_req, res) => {
  const settings = await readPanelSettings();
  res.json({ settings });
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
  const settings = await readPanelSettings();
  const user = await getUserRecordById(req.user.id);
  res.json({
    settings,
    user: sanitizeUser(user || req.user),
  });
});

app.put("/api/settings/theme", attachUser, async (req, res) => {
  const theme = normalizeTheme(req.body?.theme, "");
  if (!THEME_SET.has(theme)) {
    return res.status(400).json({ error: "theme must be light, dark, or gray" });
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

  const serverRecord = createServerRecord(valid, req.user.id);

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

  const settings = await readPanelSettings();
  const serverLimit = normalizeServerLimit(
    req.body?.server_limit,
    settings.default_server_limit
  );
  const theme = normalizeTheme(req.body?.theme, settings.default_theme);

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
    const theme = normalizeTheme(req.body.theme, "");
    if (!THEME_SET.has(theme)) {
      return res.status(400).json({ error: "theme must be light, dark, or gray" });
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
  const settings = await readPanelSettings();
  res.json({ settings });
});

app.put("/api/admin/panel-settings", attachUser, requireAdmin, async (req, res) => {
  const body = req.body || {};
  const patch = {};

  if (body.default_theme !== undefined) {
    const theme = normalizeTheme(body.default_theme, "");
    if (!THEME_SET.has(theme)) {
      return res.status(400).json({ error: "default_theme must be light, dark, or gray" });
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

app.get("/api/admin/nodes", attachUser, requireAdmin, async (_req, res) => {
  const nodes = await readJson(nodesFile, []);
  res.json({
    nodes: nodes.map((node) => ({
      ...sanitizeNode(node),
      secretMasked: node.secret ? "********" : "",
    })),
  });
});

app.post("/api/admin/nodes", attachUser, requireAdmin, async (req, res) => {
  const name = String(req.body?.name || "").trim();
  const url = String(req.body?.url || "").trim();
  const secret = String(req.body?.secret || "").trim();
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

  const nodeRecord = {
    id: idInput || `node-${crypto.randomUUID().slice(0, 8)}`,
    name,
    url: parsed.toString().replace(/\/$/, ""),
    secret,
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

app.get("/servers/:uuid/console", (_req, res) => {
  res.sendFile(path.join(publicDir, "console.html"));
});

app.get("/servers/:uuid/files", (_req, res) => {
  res.sendFile(path.join(publicDir, "files.html"));
});

app.get("/servers/:uuid/resources", (_req, res) => {
  res.sendFile(path.join(publicDir, "resources.html"));
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
