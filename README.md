# saas-installer (public)

This repo contains the **public bootstrap installer** that provisions a fresh Ubuntu VPS and deploys a selected private SaaS app from ReyadWeb.

## Architecture

- **Repo 1 (public):** this repo (`saas-installer`)
  - `saas-installer.sh` (curlable bootstrap)
  - future: an “app catalog” menu

- **Repo 2..N (private):** one repo per SaaS app (`saastest`, `saas-2`, ...)
  - Docker Compose stack
  - app-specific scripts/config

## Why this is the right structure

- Public installer stays safe (no secrets).
- Private SaaS repos remain protected; access is controlled via **SSH Deploy Keys**.
- Same installer works across many VPS + many domains.

## Security model (SSH Deploy Keys)

When you run the installer, it generates a keypair on the VPS and prints the public key.

You add that public key to the target private repo:
- GitHub → Repo → Settings → Deploy keys → Add deploy key
- Read-only recommended

Then rerun the installer and cloning will succeed.

## Quick start (fresh Ubuntu)

```bash
mkdir -p ~/installer && cd ~/installer
curl -fsSL https://raw.githubusercontent.com/ReyadWeb/saas-installer/main/saas-installer.sh -o saas-installer.sh
chmod +x saas-installer.sh
./saas-installer.sh
```

### DNS (Cloudflare)

Create an **A record** for your subdomain to the VPS public IP. Example:
- Name: `portal`  (Cloudflare appends the zone automatically)
- Target: `VPS_IP`
- Proxy: ON (orange)

Cloudflare SSL/TLS:
- **Full (strict)**

## Important: why we do NOT escape `$` in `.env`

Bcrypt hashes contain `$...$` sequences. Docker Compose may try to interpolate them and emit warnings, or break the value.

**Recommended fix (used by this installer):**
- write the hash to `caddy.env`
- load it using `env_file:` (Compose does not interpolate env_file values)

This is more reliable than the `$$` escape workaround.

## Currently supported app

1) AutoFix Pro (private repo `ReyadWeb/saastest`)
