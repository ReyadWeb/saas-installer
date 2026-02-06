# ReyadWeb SaaS Installer

A **public bootstrap repo** that installs ReyadWeb SaaS apps on a fresh **Ubuntu VPS**.

- **Public repo (this one):** installer + preflight checks + TLS setup
- **Private repos:** each SaaS app (cloned via **GitHub Deploy Key**)

Currently supported SaaS:
- **saastest (AutoFix Pro)** — Docker Compose stack (**Postgres + Node API + Caddy**)

---

## Quick start (recommended)

### 0) Prereqs (do this first)
- ✅ Ubuntu VPS + a user with `sudo`
- ✅ Domain/subdomain DNS record points to the VPS IP (e.g. `portal.example.com`)
- ✅ Ports **80** and **443** reachable from the internet (UFW can be opened by the installer)

> Cloudflare note:  
> - **Let’s Encrypt** works best if the record is **DNS only** during certificate issuance (you can switch back to proxied later).  
> - **Cloudflare Origin CA** is designed for **proxied (orange cloud)** records.

### 1) Download → inspect → run
```bash
curl -fsSL -o saas-installer.sh https://raw.githubusercontent.com/ReyadWeb/saas-installer/main/saas-installer.sh
less saas-installer.sh
bash saas-installer.sh
```

### 2) Follow the prompts
- choose the SaaS (currently **saastest**)
- enter the **domain**
- the installer will generate or ask for the **Basic Auth** password
- if the SaaS repo is private, it will print a **Deploy Key** (SSH public key)

---

## Private repo access (GitHub Deploy Key)

If the SaaS repo is private, the installer will generate a key and print the **public** part.

Add it here:
- GitHub → *private SaaS repo* → **Settings** → **Deploy keys** → **Add deploy key**
- Paste the public key
- Enable **Read access** (recommended)

Then rerun the installer.

---

## Non-interactive install (automation-friendly)

### Let’s Encrypt (default)
```bash
bash saas-installer.sh --non-interactive \
  --domain portal.example.com \
  --repo git@github.com:ReyadWeb/saastest.git \
  --tls letsencrypt \
  --yes
```

### Cloudflare Origin CA
Upload your Origin cert/key to the VPS first, then:
```bash
bash saas-installer.sh --non-interactive \
  --domain portal.example.com \
  --repo git@github.com:ReyadWeb/saastest.git \
  --tls cloudflare \
  --cf-cert /root/origin.crt \
  --cf-key  /root/origin.key \
  --yes
```

**Non-interactive note:** if the deploy key is missing in GitHub, the script prints the key and exits with code `2`. Add it, then rerun the same command.

---

## TLS provider options

### Option A — Let’s Encrypt (default)
Caddy automatically obtains a public certificate.

Requirements:
- Ports **80** and **443** open
- DNS record points to the VPS IP

Cloudflare proxy note:
- If ACME challenges fail while proxied, switch to **DNS only**, redeploy, then switch back.

### Option B — Cloudflare Origin CA
Use a Cloudflare Origin certificate (valid for Cloudflare → origin).

Important:
- Origin CA cert is **not browser-trusted**. Keep the DNS record **proxied** (orange cloud).
- Cloudflare SSL/TLS mode should be **Full (strict)**.

---

## Basic Auth password behavior

### First install
- Installer can generate a strong random password (default **Yes**)
- It prints the password **once**
- Only the **bcrypt hash** is stored (plaintext is not stored)

### If you lose the password (reset without losing DB)
```bash
bash saas-installer.sh --reset-auth
```

### Full reinstall (deletes database)
```bash
bash saas-installer.sh --reinstall --yes
```

---

## Preflight checks (built-in)
The installer checks:
- OS is Ubuntu
- minimum recommended resources (CPU/RAM/disk)
- UFW: can auto-allow ports **22/80/443**
- Docker: installs if missing

---

## After install: common commands
```bash
cd ~/apps/saastest
sudo docker compose ps
sudo docker compose logs --tail=200
sudo docker compose restart caddy
```

---

## Repo structure (recommended)

This is a good structure and scales well:

- **Repo 1 (public):** installer + menu + provisioning
- **Repo 2+ (private):** SaaS repos (each with its own `docker-compose.yml`, app code, migrations, etc.)

Tips to make it even better:
- Tag releases for the installer (e.g., `v0.1.0`) and reference a versioned URL in docs.
- Keep SaaS repos versioned (tags/branches) so updates can be pinned per VPS.
- Add a `saas.lock` file per install (records repo + commit + TLS mode + domain) for reliable upgrades.

---

## Help / flags reference
```bash
bash saas-installer.sh --help
```
