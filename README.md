# NodeDash

Production-ready AI-powered game server management platform.

## Stack
- Frontend: Next.js + TailwindCSS
- Backend: Fastify (Node.js) + Prisma + PostgreSQL + WebSocket
- Daemon: Go (`NodeDash Agent`)
- Container Engine: Docker

## Quick Start
1. Copy `.env.example` to `.env` and set strong secrets.
2. Build/start panel stack:
   `start.cmd`
3. Build/start panel + real PaperMC server:
   `start-minecraft.cmd`
4. Open panel at `http://localhost:3000`.

## DB Migration
- Generate Prisma client:
  `cd apps/api && npx prisma generate`
- Apply migrations:
  `cd apps/api && npx prisma migrate deploy`

## Security Defaults
- Access and refresh cookies are enabled.
- Refresh sessions are stored hashed in DB.
- AI provider keys are encrypted at rest.
- API rejects weak secrets in production mode.

## Monorepo
- `apps/panel` Next.js panel
- `apps/api` Fastify API
- `apps/agent` NodeDash Agent daemon
- `deploy` docker and nginx config
- `docs` architecture and API docs

