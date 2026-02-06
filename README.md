# saas-installer

Public bootstrap installer for ReyadWeb SaaS apps on a fresh Ubuntu VPS.

## Current apps

- **AutoFix Pro (saastest)** — Postgres + Node API + Caddy HTTPS + Basic Auth

## What the installer checks/does

- Verifies OS is **Ubuntu**
- Checks **CPU / RAM / Disk** minimums and warns if below recommended
- If RAM is low, offers to create a **swapfile** (helps Docker builds succeed)
- Detects **UFW** and offers to open required ports **22 / 80 / 443**
- Detects **port conflicts** on 80/443 and offers to stop common services (nginx/apache2)
- Installs Docker Engine + Compose plugin (if missing)
- Generates an SSH deploy key and prints the public key
- Clones a **private** SaaS repo using that deploy key
- Prompts for Domain + Basic Auth and starts the stack with Docker Compose

## Minimum / Recommended VPS specs

- **Minimum:** 1 vCPU, 1.5GB RAM, 10GB free disk  
- **Recommended:** 2 vCPU, 2GB+ RAM, 20GB+ free disk

## Cloudflare DNS

Create an **A record** for your SaaS subdomain pointing to the VPS IP:

- Type: `A`
- Name: `portal` (Cloudflare auto-appends the zone)
- Content: `YOUR_VPS_PUBLIC_IP`
- Proxy: ON (orange cloud) is OK

Cloudflare SSL/TLS:
- **Full (strict)**

## Run

```bash
mkdir -p ~/installer && cd ~/installer
curl -fsSL https://raw.githubusercontent.com/ReyadWeb/saas-installer/main/saas-installer.sh -o saas-installer.sh
chmod +x saas-installer.sh
./saas-installer.sh
```

## Private repo access (Deploy Key)

When the installer prints a public key:

GitHub → private repo → Settings → Deploy keys → **Add deploy key**  
Paste the public key. Read-only is recommended.

## BASIC_AUTH_HASH note

Bcrypt hashes include `$...$`, which can trigger Docker Compose interpolation warnings.

The installer writes `caddy.env` and (if needed) patches `docker-compose.yml` to load it via `env_file:`,
which avoids `$` escaping issues.
