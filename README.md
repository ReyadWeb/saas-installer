# SaaS Installer (ReyadWeb)

A small **public bootstrap installer** that provisions a fresh **Ubuntu** VPS and deploys a selected ReyadWeb SaaS app from a **private GitHub repo** (via SSH deploy key).

Current supported app:
- **AutoFix Pro (saastest)** — Docker Compose stack: Postgres + Node API + Caddy + Basic Auth

---

## What this installer does

- Validates you are on **Ubuntu** (supported: 22.04 / 24.04)
- Installs required dependencies (git, curl, docker, compose plugin, etc.)
- Optionally checks / opens firewall ports (80/443 and SSH)
- Prompts for:
  - **Domain** (FQDN, e.g. `portal.example.com`)
  - **TLS provider**
    - **Let's Encrypt** (recommended; works with Cloudflare orange-cloud or DNS-only)
    - **Cloudflare Origin CA** (manual cert/key)
  - **Private repo SSH URL** + optional branch
- Generates (or reuses) an **SSH deploy key** and prints the public key so you can add it to the private repo.
- Clones the private repo and runs `docker compose up -d --build`
- Prints the final URL when done

---

## Prerequisites (before you run it)

### 1) Create a sudo user (don’t use root)
On a fresh VPS:

```bash
adduser deploy-1
usermod -aG sudo deploy-1
```

Log out and back in as `deploy-1`.

### 2) Point your domain to the VPS
Create a DNS **A record**:

- `portal.example.com` → **YOUR_VPS_PUBLIC_IP**

If you use **Cloudflare**:
- Orange-cloud (proxied) is OK.
- Set SSL mode to **Full (strict)**.
- You do **not** need to install a Cloudflare certificate on the VPS if you use **Let's Encrypt** on the origin (Caddy handles this).

---

## Install

### Option A (recommended): download then run

```bash
curl -fsSL https://raw.githubusercontent.com/ReyadWeb/saas-installer/main/saas-installer.sh -o saas-installer.sh
chmod +x saas-installer.sh
./saas-installer.sh
```

### Option B: one-liner (less safe)

```bash
curl -fsSL https://raw.githubusercontent.com/ReyadWeb/saas-installer/main/saas-installer.sh | bash
```

---

## Private repo access (SSH deploy key)

During install, the script prints a public key like:

```
ssh-ed25519 AAAA... saas-installer@hostname
```

Add it in GitHub:
- Private repo → **Settings** → **Deploy keys** → **Add deploy key**
- Check **Allow read access** (recommended)

Then press Enter in the installer to retry cloning.

---

## After install

- The app will be available at: `https://YOUR_DOMAIN`
- Basic Auth is enforced at the edge (Caddy).
- The installer will show a generated password only once — **copy it** and store it securely.

To reset Basic Auth later, re-run the installer and choose the reset option (or use the documented reset command shown by the script).

---

## Common issues

### “Hi … GitHub does not provide shell access.”
This is normal. It means the SSH key authentication succeeded.

### Cloudflare error **525**
Most common causes:
- Origin container not serving TLS yet / Caddy is restarting
- Wrong domain passed to the installer (or missing `APP_DOMAIN` in container env)
- Cloudflare SSL mode set incorrectly

Fix:
- Confirm the stack is up: `sudo docker compose ps`
- Check Caddy logs: `sudo docker compose logs -n 200 caddy`
- Ensure Cloudflare SSL mode is **Full (strict)** and DNS points to the correct IP.

---

## Security notes

- This installer will run privileged operations via **sudo**.
- Prefer “Option A” (download then run), and review the script before executing.
- Treat the deploy key as sensitive. If it ever leaks, rotate it in GitHub.

