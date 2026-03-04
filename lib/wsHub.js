const { WebSocketServer } = require("ws");
const { URL } = require("url");

function safeSend(ws, payload) {
  if (ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify(payload));
  }
}

function createWsHub({ server, verifyClient }) {
  const wss = new WebSocketServer({ noServer: true });
  const clients = new Set();

  server.on("upgrade", async (request, socket, head) => {
    try {
      const url = new URL(request.url, "http://localhost");
      if (url.pathname !== "/ws") {
        socket.destroy();
        return;
      }

      const token = url.searchParams.get("token");
      if (!token) {
        socket.destroy();
        return;
      }

      const user = await verifyClient(token);
      if (!user) {
        socket.destroy();
        return;
      }

      wss.handleUpgrade(request, socket, head, (ws) => {
        ws.user = user;
        ws.subscriptions = new Set();
        wss.emit("connection", ws, request);
      });
    } catch {
      socket.destroy();
    }
  });

  wss.on("connection", (ws) => {
    clients.add(ws);
    safeSend(ws, { type: "connected", user: ws.user });

    ws.on("message", (raw) => {
      let msg;
      try {
        msg = JSON.parse(raw.toString());
      } catch {
        safeSend(ws, { type: "error", error: "Invalid JSON" });
        return;
      }

      if (msg.type === "subscribe" && msg.channel === "server" && msg.uuid) {
        ws.subscriptions.add(msg.uuid);
        safeSend(ws, {
          type: "subscribed",
          channel: "server",
          uuid: msg.uuid,
        });
        return;
      }

      if (msg.type === "unsubscribe" && msg.channel === "server" && msg.uuid) {
        ws.subscriptions.delete(msg.uuid);
        safeSend(ws, {
          type: "unsubscribed",
          channel: "server",
          uuid: msg.uuid,
        });
        return;
      }

      safeSend(ws, { type: "error", error: "Unsupported message" });
    });

    ws.on("close", () => {
      clients.delete(ws);
    });
  });

  function broadcastServerEvent(uuid, event) {
    for (const ws of clients) {
      if (ws.subscriptions.has(uuid)) {
        safeSend(ws, {
          type: "server_event",
          uuid,
          event,
        });
      }
    }
  }

  function broadcastNodeEvent(event) {
    for (const ws of clients) {
      safeSend(ws, {
        type: "node_event",
        event,
      });
    }
  }

  return {
    broadcastServerEvent,
    broadcastNodeEvent,
  };
}

module.exports = {
  createWsHub,
};
