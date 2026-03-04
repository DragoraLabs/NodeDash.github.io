const fs = require("fs/promises");
const path = require("path");

const locks = new Map();

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

async function ensureJson(filePath, defaultValue) {
  try {
    await fs.access(filePath);
  } catch {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, JSON.stringify(defaultValue, null, 2));
  }
}

async function readJson(filePath, defaultValue) {
  await ensureJson(filePath, defaultValue);
  const raw = await fs.readFile(filePath, "utf8");
  try {
    return JSON.parse(raw);
  } catch {
    await writeJson(filePath, clone(defaultValue));
    return clone(defaultValue);
  }
}

async function writeJson(filePath, data) {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const tmpPath = `${filePath}.tmp`;
  const body = JSON.stringify(data, null, 2);
  await fs.writeFile(tmpPath, body, "utf8");
  await fs.rename(tmpPath, filePath);
}

function withLock(filePath, task) {
  const pending = locks.get(filePath) || Promise.resolve();
  const run = pending.then(task, task);
  locks.set(
    filePath,
    run.catch(() => {
      // Keep lock chain alive after errors.
    })
  );
  return run;
}

async function updateJson(filePath, defaultValue, mutator) {
  return withLock(filePath, async () => {
    const current = await readJson(filePath, defaultValue);
    const next = (await mutator(clone(current))) ?? current;
    await writeJson(filePath, next);
    return next;
  });
}

module.exports = {
  readJson,
  writeJson,
  updateJson,
};
