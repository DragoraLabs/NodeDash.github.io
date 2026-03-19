param()
$ErrorActionPreference='Stop'
$base = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location "$base\panel"

if (!(Test-Path .env)) { Copy-Item .env.example .env }
if (!(Test-Path certs)) { New-Item -ItemType Directory certs | Out-Null }

npm install

if (!(Test-Path certs\panel.key) -or !(Test-Path certs\panel.crt)) {
  node scripts\gen-cert.js
}

Write-Host 'Panel ready. Run: npm start'
