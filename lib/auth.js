const path = require("path");
const { readJson, updateJson } = require("./dataStore");
const { verifyToken } = require("./security");

function createAuth(dataDir) {
  const usersFile = path.join(dataDir, "users.json");
  const sessionsFile = path.join(dataDir, "sessions.json");

  function sanitizeUser(user) {
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      theme: user.theme || "gray",
      server_limit: Number.isFinite(Number(user.server_limit))
        ? Number(user.server_limit)
        : 1,
    };
  }

  function parseCookies(req) {
    const raw = req.headers.cookie || "";
    const cookies = {};
    for (const part of raw.split(";")) {
      const [k, ...rest] = part.trim().split("=");
      if (!k) continue;
      cookies[k] = decodeURIComponent(rest.join("=") || "");
    }
    return cookies;
  }

  function getBearerToken(req) {
    const authHeader = req.headers.authorization || "";
    const [type, token] = authHeader.split(" ");
    if (type === "Bearer" && token) {
      return token;
    }

    const cookies = parseCookies(req);
    return cookies.nodewings_token || null;
  }

  async function cleanupSessions() {
    await updateJson(sessionsFile, [], (sessions) => {
      const now = Date.now();
      return sessions.filter((session) => {
        return new Date(session.expiresAt).getTime() > now;
      });
    });
  }

  async function attachUser(req, res, next) {
    try {
      await cleanupSessions();

      const token = getBearerToken(req);
      if (!token) {
        return res.status(401).json({ error: "Missing bearer token" });
      }

      const decoded = verifyToken(token);
      const sessions = await readJson(sessionsFile, []);
      const session = sessions.find((item) => item.sid === decoded.sid);
      if (!session) {
        return res.status(401).json({ error: "Session expired" });
      }

      const users = await readJson(usersFile, []);
      const user = users.find((item) => item.id === decoded.sub);
      if (!user) {
        return res.status(401).json({ error: "User not found" });
      }

      req.user = sanitizeUser(user);
      req.userRecord = user;
      req.token = token;
      req.session = session;
      return next();
    } catch {
      return res.status(401).json({ error: "Invalid token" });
    }
  }

  function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
      return res.status(403).json({ error: "Admin access required" });
    }
    return next();
  }

  return {
    attachUser,
    requireAdmin,
    sanitizeUser,
    parseCookies,
    getBearerToken,
  };
}

module.exports = {
  createAuth,
};
