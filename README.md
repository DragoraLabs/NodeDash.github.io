# NodeDash / NodeWings (No DB)

This build uses **JSON files only** for persistence. No database.

Folders:
- `d:\NodeDash\nodedash` (Panel)
- `d:\NodeDash\nodedash-wings` (Agent + C++)

## Panel (VPS 1)

```powershell
cd d:\NodeDash\nodedash
.\install-panel.ps1
cd panel
npm start
```

Open `https://127.0.0.1:8443`

## Wings (VPS 2)

```powershell
cd d:\NodeDash\nodedash-wings
.\install-wings.ps1
.\build-cpp.ps1
python wings.py
```

## Node registration flow
1. Login to panel (first user becomes admin)
2. Create node in Admin > Nodes
3. Edit `d:\NodeDash\nodedash-wings\config.json` with:
   - `panel_url`
   - `node_id`
   - `node_token`
4. Start Wings; it auto-auths to panel and begins heartbeats

## Data files
Panel stores data in `d:\NodeDash\nodedash\panel\data`:
- `users.json`
- `servers.json`
- `nodes.json`
- `api_keys.json`
- `panel_settings.json`
- `security.json`
- `sessions.json`

Wings stores server configs in `d:\NodeDash\nodedash-wings\data\servers.json`

## Notes
- Docker must be installed on Wings host.
- C++ manager `dockermgr` wraps Docker CLI for container lifecycle and limits.
