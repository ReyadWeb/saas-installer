# saas-installer (public)

This repository is the **public bootstrap installer** that provisions a fresh Ubuntu VPS and deploys a selected **private** ReyadWeb SaaS app.

## Architecture

- **Repo 1 (public):** `saas-installer` (this repo)
  - `saas-installer.sh` (curlable bootstrap + app catalog)

- **Repo 2..N (private):** one repo per SaaS app (`saastest`, `saas-2`, ...)
  - Docker Compose stack + app code
  - app-specific scripts/config

This structure scales well for installing different SaaS apps across **different domains** and **different VPS** instances.

## Security model (SSH Deploy Keys)

The installer generates an SSH keypair on the VPS and prints the **public key**.

You add that public key to the target private repo as a **Deploy Key**:
- GitHub → Private repo → Settings → Deploy keys → Add deploy key
- **Read-only recommended**

Only a VPS with an authorized deploy key can clone the private repo.

## Quick start (fresh Ubuntu)

On the VPS:

```bash
mkdir -p ~/installer && cd ~/installer
curl -fsSL https://raw.githubusercontent.com/ReyadWeb/saas-installer/main/saas-installer.sh -o saas-installer.sh
chmod +x saas-installer.sh
./saas-installer.sh
```

The script will prompt you for:
- Domain (FQDN), e.g. `portal.example.com`
- Which SaaS app to install (currently: **1 app**)
- Private repo SSH URL (defaults to `git@github.com:ReyadWeb/saastest.git`)
- Basic Auth user/password (for SaaS #1)

## Cloudflare DNS

Create an **A record** for the subdomain pointing to the VPS IP:

- Type: `A`
- Name: `portal`  (Cloudflare appends your zone automatically)
- Content: `YOUR_VPS_PUBLIC_IP`
- Proxy: ON (orange cloud)

Cloudflare SSL/TLS:
- **Full (strict)**

## Important: Avoid bcrypt `$` interpolation in Docker Compose

Bcrypt hashes contain `$...$` sequences. Docker Compose may try to interpolate them and print warnings or break the value.

**Recommended pattern (used by the installer):**
- Put DB/app config in `.env`
- Put `APP_DOMAIN`, `BASIC_AUTH_USER`, `BASIC_AUTH_HASH` in `caddy.env`
- Load `caddy.env` with `env_file:` in `docker-compose.yml`

This avoids the fragile `$$` escaping workaround.

## Currently supported SaaS app

### 1) AutoFix Pro (saastest)
Private repo: `git@github.com:ReyadWeb/saastest.git`
