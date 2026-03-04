const crypto = require("crypto");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "dev-change-me-jwt-secret";
const JWT_TTL_SECONDS = Number(process.env.JWT_TTL_SECONDS || 60 * 60 * 24);

function toBase64(input) {
  return Buffer.from(input).toString("base64url");
}

function fromBase64(input) {
  return Buffer.from(input, "base64url").toString("utf8");
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const iterations = 120000;
  const keylen = 32;
  const digest = "sha256";
  const hash = crypto
    .pbkdf2Sync(password, salt, iterations, keylen, digest)
    .toString("hex");

  return toBase64(
    JSON.stringify({
      algo: "pbkdf2",
      iterations,
      keylen,
      digest,
      salt,
      hash,
    })
  );
}

function verifyPassword(password, encoded) {
  if (!encoded) {
    return false;
  }

  let payload;
  try {
    payload = JSON.parse(fromBase64(encoded));
  } catch {
    return false;
  }

  if (!payload || payload.algo !== "pbkdf2") {
    return false;
  }

  const computed = crypto
    .pbkdf2Sync(
      password,
      payload.salt,
      payload.iterations,
      payload.keylen,
      payload.digest
    )
    .toString("hex");

  const a = Buffer.from(computed, "hex");
  const b = Buffer.from(payload.hash, "hex");

  if (a.length !== b.length) {
    return false;
  }

  return crypto.timingSafeEqual(a, b);
}

function issueToken(user) {
  const sid = crypto.randomUUID();
  const token = jwt.sign(
    {
      sub: user.id,
      email: user.email,
      role: user.role,
      sid,
    },
    JWT_SECRET,
    { expiresIn: JWT_TTL_SECONDS }
  );

  return {
    token,
    sid,
    expiresAt: new Date(Date.now() + JWT_TTL_SECONDS * 1000).toISOString(),
  };
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

module.exports = {
  hashPassword,
  verifyPassword,
  issueToken,
  verifyToken,
};
