# NodeDash 🚀

**Power • Control • Scale**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/DragoraLabs/NodeDash/blob/main/LICENSE)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)](https://nodejs.org)
[![Express](https://img.shields.io/badge/Express-4.x-black)](https://expressjs.com)
[![WebSockets](https://img.shields.io/badge/WebSockets-Live-blue)](https://github.com/DragoraLabs/NodeDash)

**The open-source server management panel** built for game hosts, cloud providers, and devs who want **real control** without the bloat or price tag.

Tired of overpriced panels that lock you in?  
NodeDash gives you **full ownership** — manage servers, nodes, users, files, and real-time stats with a clean, fast interface.

**Live Marketing Site & Demo:** [nodedash.gamerhost.qzz.io](https://nodedash.gamerhost.qzz.io/)  
**GitHub Pages (extra assets):** [nodedash.github.io](https://github.com/DragoraLabs/nodedash.github.io)

---

## ✨ Why NodeDash?

- **Full Customization** — Dynamic themes, per-user server limits, admin-controlled UI, and panel settings saved in JSON.
- **Advanced Security** — JWT + secure cookies, role-based access (admin/user), rate limiting, input validation, and internal node authentication.
- **Real-Time Everything** — WebSocket hub for live updates, console, server events, and heartbeats.
- **Modular & Scalable** — Built-in Wings client for talking to remote nodes. Easy to add plugins later.
- **Multi-Language Runtimes** — Node.js & Python servers out of the box with custom start commands.
- **Lightweight & Fast** — No heavy frameworks. Just Express + vanilla frontend + JSON storage (swap to DB anytime).
- **100% Free & Open** — MIT license. No vendor lock-in. Run it on Linux, Windows, Docker, VPS, or bare metal.

---

## 📸 Screenshots

![NodeDash Control Plane](https://github.com/DragoraLabs/nodedash.github.io/raw/main/Screenshot%202026-03-07%20161541.png)

*(More screenshots coming as we polish the UI — dashboard, servers, console, nodes, and admin panels are already live!)*

---

## 🚀 Quick Start (Takes 2 Minutes)

```bash
# 1. Clone the repo
git clone https://github.com/DragoraLabs/NodeDash.git
cd NodeDash

# 2. Install dependencies
npm install

# 3. (Optional) Set environment variables
#    Create a .env file or export these:
#    DEFAULT_ADMIN_EMAIL=admin@example.com
#    DEFAULT_ADMIN_PASSWORD=admin123
#    PORT=3000
#    HOST=0.0.0.0

# 4. Start the panel
npm start
