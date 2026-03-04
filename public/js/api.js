(function () {
  const tokenKey = "nodewings_token";
  let panelSettingsCache = null;

  function escapeHtml(value) {
    return String(value || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function readCookie(name) {
    const parts = document.cookie ? document.cookie.split(";") : [];
    for (const part of parts) {
      const [key, ...rest] = part.trim().split("=");
      if (key === name) {
        return decodeURIComponent(rest.join("=") || "");
      }
    }
    return "";
  }

  function getToken() {
    return localStorage.getItem(tokenKey) || "";
  }

  function setToken(token) {
    localStorage.setItem(tokenKey, token);
    document.cookie = `${tokenKey}=${encodeURIComponent(token)}; Path=/; SameSite=Lax; Max-Age=${60 * 60 * 24}`;
  }

  function clearToken() {
    localStorage.removeItem(tokenKey);
    document.cookie = `${tokenKey}=; Path=/; SameSite=Lax; Max-Age=0`;
  }

  async function api(path, options = {}) {
    const config = {
      method: options.method || "GET",
      headers: {
        ...(options.body !== undefined ? { "Content-Type": "application/json" } : {}),
        ...(options.headers || {}),
      },
    };

    if (options.body !== undefined) {
      config.body = JSON.stringify(options.body);
    }

    const token = getToken();
    if (options.auth !== false && token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    const response = await fetch(path, config);
    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }

    if (!response.ok) {
      const error = new Error(data.error || data.raw || response.statusText);
      error.status = response.status;
      throw error;
    }

    return data;
  }

  function showError(target, message) {
    if (!target) return;
    target.textContent = message;
    target.style.color = "#bf2f2f";
  }

  function showInfo(target, message, ok = true) {
    if (!target) return;
    target.textContent = message;
    target.style.color = ok ? "#1d7f4e" : "#bf2f2f";
  }

  function shadeHex(color, amount) {
    const hex = String(color || "").trim();
    if (!/^#[0-9a-fA-F]{6}$/.test(hex)) {
      return color;
    }

    const raw = hex.slice(1);
    const next = [0, 2, 4]
      .map((idx) => {
        const value = parseInt(raw.slice(idx, idx + 2), 16);
        const shaded = Math.max(0, Math.min(255, value + amount));
        return shaded.toString(16).padStart(2, "0");
      })
      .join("");

    return `#${next}`;
  }

  function applyTheme(settings, userTheme) {
    const root = document.documentElement;
    const theme = String(userTheme || settings.default_theme || "gray").toLowerCase();
    root.setAttribute("data-theme", theme);

    root.style.setProperty("--sidebar-color", settings.sidebar_color || "#2f2f2f");
    root.style.setProperty("--card-color", settings.card_color || "#ffffff");
    root.style.setProperty("--button-color", settings.button_color || "#4a4a4a");
    root.style.setProperty("--button-color-hover", shadeHex(settings.button_color || "#4a4a4a", -18));

    if (theme === "dark") {
      root.style.setProperty("--bg-color", "#17191d");
      root.style.setProperty("--text-color", "#eceef1");
      root.style.setProperty("--muted-color", "#9ca4b0");
      root.style.setProperty("--line-color", "#30343b");
      root.style.setProperty("--input-bg", "#23272f");
      root.style.setProperty("--input-text", "#eceef1");
      root.style.setProperty("--table-head", "#242932");
      root.style.setProperty("--hover-bg", "rgba(255,255,255,0.05)");
    } else if (theme === "light") {
      root.style.setProperty("--bg-color", "#fafafa");
      root.style.setProperty("--text-color", "#1d1f23");
      root.style.setProperty("--muted-color", "#656d78");
      root.style.setProperty("--line-color", "#dfdfdf");
      root.style.setProperty("--input-bg", "#ffffff");
      root.style.setProperty("--input-text", "#1d1f23");
      root.style.setProperty("--table-head", "#f2f3f5");
      root.style.setProperty("--hover-bg", "rgba(0,0,0,0.03)");
    } else {
      root.style.setProperty("--bg-color", "#f4f4f4");
      root.style.setProperty("--text-color", "#24262a");
      root.style.setProperty("--muted-color", "#5f6670");
      root.style.setProperty("--line-color", "#d8d8d8");
      root.style.setProperty("--input-bg", "#ffffff");
      root.style.setProperty("--input-text", "#24262a");
      root.style.setProperty("--table-head", "#ececec");
      root.style.setProperty("--hover-bg", "rgba(0,0,0,0.035)");
    }
  }

  async function loadPanelSettings() {
    if (!panelSettingsCache) {
      const payload = await api("/api/panel-settings", { auth: false });
      panelSettingsCache = payload.settings;
    }
    return panelSettingsCache;
  }

  function injectPageBanner(title, user) {
    const main = document.querySelector("main");
    if (!main || main.querySelector(".page-banner")) {
      return;
    }

    const banner = document.createElement("section");
    banner.className = "page-banner";
    banner.innerHTML = `
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(user.name || user.email)} · ${escapeHtml(user.role || "user")}</p>
    `;
    main.prepend(banner);
  }

  function renderHeader(title, user) {
    const header = document.getElementById("header");
    if (!header) return;

    document.body.classList.remove("auth-page");
    document.body.classList.add("app-page");

    const path = location.pathname;
    const links = [
      { href: "/dashboard", label: "Dashboard", active: path === "/dashboard" || path === "/" },
      { href: "/servers", label: "Servers", active: path === "/servers" || /^\/servers\//.test(path) },
      { href: "/nodes", label: "Nodes", active: path === "/nodes" },
      { href: "/settings", label: "Settings", active: path === "/settings" },
    ];

    if (user && user.role === "admin") {
      links.push({ href: "/admin", label: "Admin Panel", active: path === "/admin" });
    }

    const linksHtml = links
      .map((item) => `<a href="${item.href}" class="${item.active ? "active" : ""}">${item.label}</a>`)
      .join("");

    header.innerHTML = `
      <aside class="sidebar">
        <div class="sidebar-brand">
          <div class="brand-badge">NW</div>
          <div>
            <div class="brand-title">NodeWings</div>
            <div class="brand-subtitle">Panel</div>
          </div>
        </div>
        <nav class="sidebar-nav">${linksHtml}</nav>
        <div class="sidebar-footer">
          <div class="sidebar-user">${escapeHtml(user?.email || "Unknown")}</div>
          <button id="logoutBtn" class="secondary full">Logout</button>
        </div>
      </aside>
    `;

    const logoutBtn = header.querySelector("#logoutBtn");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", async () => {
        await logout();
      });
    }

    injectPageBanner(title, user || {});
  }

  function renderLoginHeader() {
    const header = document.getElementById("header");
    if (!header) return;

    document.body.classList.remove("app-page");
    document.body.classList.add("auth-page");

    header.innerHTML = `
      <div class="auth-topbar">
        <div class="auth-brand">
          <div class="brand-badge">NW</div>
          <div>
            <div class="brand-title">NodeWings</div>
            <div class="brand-subtitle">Sign in</div>
          </div>
        </div>
      </div>
    `;
  }

  async function requireAuth() {
    try {
      const payload = await api("/api/auth/me");
      return payload.user;
    } catch {
      clearToken();
      location.href = "/login";
      return null;
    }
  }

  async function logout() {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } catch {
      // Ignore logout errors and clear local state.
    }
    clearToken();
    location.href = "/login";
  }

  async function initPage(title, options = {}) {
    const user = await requireAuth();
    if (!user) {
      return null;
    }

    if (options.adminOnly && user.role !== "admin") {
      location.href = "/forbidden";
      return null;
    }

    try {
      const payload = await api("/api/settings");
      applyTheme(payload.settings, payload.user?.theme || user.theme);
      renderHeader(title, payload.user || user);
      return payload.user || user;
    } catch {
      try {
        const settings = await loadPanelSettings();
        applyTheme(settings, user.theme || settings.default_theme);
      } catch {
        // Keep CSS defaults if settings fetch fails.
      }
      renderHeader(title, user);
      return user;
    }
  }

  async function initLoginPage() {
    renderLoginHeader();
    try {
      const settings = await loadPanelSettings();
      applyTheme(settings, settings.default_theme);
    } catch {
      // Keep CSS defaults.
    }
  }

  function parseServerUuidFromPath() {
    const parts = location.pathname.split("/").filter(Boolean);
    const serversIndex = parts.indexOf("servers");
    if (serversIndex < 0 || parts.length <= serversIndex + 1) {
      return null;
    }
    return parts[serversIndex + 1];
  }

  function connectServerSocket(token, onEvent) {
    const wsProtocol = location.protocol === "https:" ? "wss" : "ws";
    const authToken = token || getToken() || readCookie(tokenKey);
    const query = authToken ? `?token=${encodeURIComponent(authToken)}` : "";
    const ws = new WebSocket(`${wsProtocol}://${location.host}/ws${query}`);

    ws.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);
        onEvent(parsed);
      } catch {
        // Ignore malformed websocket payloads.
      }
    };

    return ws;
  }

  window.NodeWings = {
    api,
    getToken,
    setToken,
    clearToken,
    showError,
    showInfo,
    loadPanelSettings,
    applyTheme,
    requireAuth,
    logout,
    renderHeader,
    renderLoginHeader,
    initPage,
    initLoginPage,
    parseServerUuidFromPath,
    connectServerSocket,
  };
})();
