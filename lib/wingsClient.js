async function postJson(url, secret, body, timeoutMs = 12000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-node-secret": secret,
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    const text = await response.text();
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = { raw: text };
    }

    if (!response.ok) {
      const message = parsed.error || parsed.raw || response.statusText;
      throw new Error(`Wings error ${response.status}: ${message}`);
    }

    return parsed;
  } finally {
    clearTimeout(timer);
  }
}

async function callNodeCommand(node, payload) {
  return postJson(`${node.url.replace(/\/$/, "")}/command`, node.secret, payload);
}

async function callNodeFiles(node, payload) {
  return postJson(`${node.url.replace(/\/$/, "")}/files`, node.secret, payload);
}

module.exports = {
  callNodeCommand,
  callNodeFiles,
};
