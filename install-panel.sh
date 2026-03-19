#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/panel"
[ -f .env ] || cp .env.example .env
mkdir -p certs
npm install
node scripts/gen-cert.js
