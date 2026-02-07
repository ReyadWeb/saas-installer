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
  - **TLS mode**
    - **Let's Encrypt** (direct DNS / no proxy)
    - **Cloudflare proxied + Let's Encrypt on origin** (orange cloud, no Origin cert files)
    - **Cloudflare Origin CA** (Full (strict) with Origin cert/key files on the VPS)
    - **Cloudflare proxied + internal TLS** (bootstrap; no cert files; set Cloudflare SSL/TLS to Full (not strict))
- After deployment (Cloudflare modes), runs an automatic **Cloudflare / HTTPS health check** that:
  - Validates DNS resolution for the domain
  - Detects whether the request is proxied by Cloudflare
  - Flags common Cloudflare edge errors (525/526/522/523/524) and prints the **single next step** to fix it


### Run the health check later (no redeploy)

If you changed DNS / Cloudflare SSL settings and want to diagnose **525/526/522** without reinstalling:

**From the deployment directory** (recommended):

```bash
cd ~/apps/saastest
bash saas-installer.sh --health-check-only
```

**From anywhere** (explicit):

```bash
bash saas-installer.sh --health-check-only   --target-dir ~/apps/saastest   --domain portal.example.com   --tls cloudflare-internal
```

Notes:
- If `--domain` is omitted, the installer tries to read `APP_DOMAIN=` from `caddy.env` (or infer from Caddyfile).
- If `--target-dir` is omitted, it uses the current directory if it contains `docker-compose.yml`; otherwise it computes the path from `--base-dir` + `--repo`.

  - **Private repo SSH URL** + optional branch
- Generates (or reuses) an **SSH deploy key** and prints the public key so you can add it to the private repo.
- Clones the private repo and runs `docker compose up -d --build`
- Prints the final URL when done

---


### Machine-readable health check (JSON)

Run the health check and emit **one JSON object** to stdout (useful for CI/support tickets):

```bash
bash saas-installer.sh --health-check-only --health-check-json
```

During a normal deploy, `--health-check-json` writes the result to:

- `<deploy_dir>/saas-healthcheck.json`

**`result_code` field (stable enum)**

The JSON includes a `result_code` you can use for automation / support triage. Current values:

- `ok`
- `dns_no_resolution`
- `curl_missing`
- `proxy_expected_off`
- `cf_525_ssl_handshake_failed`
- `cf_526_invalid_origin_cert`
- `cf_522_origin_timeout`
- `cf_523_origin_unreachable`
- `cf_524_origin_timeout`
- `request_failed`
- `direct_dns_mismatch_public_ip`
- `unexpected_status`

The numeric HTTP status is still reported separately as `https_status`.



## Prerequisites (before you run it)

### 1) Create a sudo user (don’t use root)
On a fresh VPS:

```bash
adduser deploy-1
usermod -aG sudo deploy-1
```

Log out and back in as `deploy-1`.

> Cloudflare note: if you use orange-cloud proxy and see **HTTP 525**, your Cloudflare SSL mode is stricter than your origin TLS.
> - **cloudflare-le**: temporarily switch Cloudflare SSL/TLS to **Full** (not strict) or set DNS to **DNS only** until the Let's Encrypt cert is issued, then switch back to **Full (strict)**.
> - **cloudflare-internal**: Cloudflare must stay on **Full (not strict)** (the origin uses Caddy `tls internal`, which is self-signed).

### 2) Point your domain to the VPS
Create a DNS **A record**:

- `portal.example.com` → **YOUR_VPS_PUBLIC_IP**

If you use **Cloudflare**:
- Orange-cloud (proxied) is OK.
- SSL/TLS mode depends on the TLS mode you choose:
  - **cloudflare-le**: **Full (strict)** (after the origin cert is issued)
  - **cloudflare-origin**: **Full (strict)**
  - **cloudflare-internal**: **Full (not strict)** (bootstrap / self-signed origin cert)

- You do **not** need to install a Cloudflare Origin CA certificate on the VPS if you use **cloudflare-le** (Caddy gets a public cert via Let's Encrypt).

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
- Ensure Cloudflare SSL mode matches your installer TLS mode: **Full (strict)** for **cloudflare-le**/**cloudflare-origin**, **Full (not strict)** for **cloudflare-internal**. Confirm DNS points to the correct IP.

---

## Security notes

- This installer will run privileged operations via **sudo**.
- Prefer “Option A” (download then run), and review the script before executing.
- Treat the deploy key as sensitive. If it ever leaks, rotate it in GitHub.
