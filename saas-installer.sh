#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# ReyadWeb SaaS Installer (public bootstrap)
#
# Supports:
# - Ubuntu preflight checks (OS, resources, ports/UFW)
# - Private repo clone via SSH deploy key (read-only recommended)
# - Docker install (official Docker repo)
# - AutoFix Pro (saastest) deployment via Docker Compose
#
# TLS modes:
#   --tls letsencrypt           (default, Caddy Automatic HTTPS)
#   --tls cloudflare-le         (Cloudflare proxied + Let's Encrypt on origin; no cert files)
#   --tls cloudflare-origin     (Cloudflare Origin CA cert/key files; no public trust)
#   --tls cloudflare-internal   (Cloudflare proxied + Caddy internal TLS; bootstrap / no files)
#
#   NOTE: --tls cloudflare is an alias: it maps to cloudflare-le unless --cf-cert/--cf-key are provided.
# Non-interactive mode:
#   --non-interactive + required flags (see README)
#
# Reset flows:
#   --reset-auth   Regenerate Basic Auth credentials (keeps DB/data)
#   --reinstall    Destroy containers + volumes (wipes DB/data) and redeploy
# ============================================================

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "WARN: $*" >&2; }

# ------------------------- Defaults --------------------------
DEFAULT_BASE_DIR="$HOME/apps"
DEFAULT_APP_ID="1"
DEFAULT_REPO_SSH="git@github.com:ReyadWeb/saastest.git"
DEFAULT_BRANCH=""

MIN_CPU_CORES=2
MIN_RAM_MB=2048
MIN_DISK_GB=12

# -------------------- Runtime flags/state --------------------
RESET_AUTH=0
FULL_REINSTALL=0
NON_INTERACTIVE=0
ASSUME_YES=0
UFW_AUTO_ALLOW=0
UFW_SKIP=0
HEALTH_CHECK_ONLY=0
HEALTH_CHECK_JSON=0
HEALTH_CHECK_JSON_FILE=""


APP_ID="$DEFAULT_APP_ID"
BASE_DIR=""
TARGET_DIR=""
APP_DOMAIN=""
TLS_PROVIDER_NAME="letsencrypt"  # letsencrypt | cloudflare-le | cloudflare-origin | cloudflare-internal
REPO_SSH=""
BRANCH=""
BASIC_AUTH_USER=""
BASIC_AUTH_PASS=""
BASIC_AUTH_GEN="auto"            # auto | yes | no

CF_CERT_PATH=""
CF_KEY_PATH=""

# ------------------------- Usage -----------------------------
usage() {
  cat <<'EOF'
Usage:
  Interactive:
    bash saas-installer.sh

  Non-interactive (recommended for automation):
    bash saas-installer.sh --non-interactive \
      --domain portal.example.com \
      --repo git@github.com:ReyadWeb/saastest.git \
      --tls letsencrypt \
      --yes

  Cloudflare Origin CA non-interactive:
    bash saas-installer.sh --non-interactive \
      --domain portal.example.com \
      --repo git@github.com:ReyadWeb/saastest.git \
      --tls cloudflare-origin \
      --cf-cert /path/to/origin.crt \
      --cf-key  /path/to/origin.key \
      --yes

  Cloudflare proxied + internal TLS (bootstrap; no cert files):
    bash saas-installer.sh --non-interactive \
      --domain portal.example.com \
      --repo git@github.com:ReyadWeb/saastest.git \
      --tls cloudflare-internal \
      --yes

Flags:
  --app <id>                 App selection (default: 1)
  --base-dir <path>          Install base dir (default: ~/apps)
  --domain <fqdn>            Required in non-interactive mode
  --repo <ssh_url>           Private repo SSH URL (default: ReyadWeb/saastest)
  --branch <name>            Git branch (optional)

  --tls <letsencrypt|cloudflare|cloudflare-le|cloudflare-origin|cloudflare-internal>  TLS mode (default: letsencrypt)
                               - letsencrypt: public cert via Let's Encrypt (direct / DNS only)
                               - cloudflare / cloudflare-le: Cloudflare proxied + Let's Encrypt on origin (no cert files)
                               - cloudflare-origin: Cloudflare Origin CA (requires --cf-cert/--cf-key)
                               - cloudflare-internal: Cloudflare proxied + Caddy internal TLS (bootstrap; set Cloudflare SSL to Full)
  --cf-cert <path>           Cloudflare Origin cert path (required if --tls cloudflare-origin in non-interactive)
  --cf-key <path>            Cloudflare Origin key path  (required if --tls cloudflare-origin in non-interactive)

  --basic-user <user>        Basic Auth username (default: admin)
  --basic-pass <pass>        Basic Auth plaintext password (will be hashed)
  --gen-pass                 Force generate random password
  --no-gen-pass              Disable generation (will prompt in interactive, or require --basic-pass in non-interactive)

  --ufw-auto-allow            If UFW active, auto-allow ports 22/80/443 (non-interactive friendly)
  --ufw-skip                  Skip UFW changes even if active
  --yes                       Assume "yes" to prompts where safe (resource warning, etc.)
  --non-interactive            No prompts. Errors if required inputs missing.

  --reset-auth                Regenerate Basic Auth credentials (keeps DB/data)
  --reinstall                 Full reinstall (removes volumes; deletes DB/data)

  --health-check-only          Run Cloudflare/HTTPS health check ONLY
  --health-check-json          Output health check result as JSON (stdout in --health-check-only mode; file during full deploy).
 (no install/deploy). Useful for diagnosing 525/526/522 after DNS/SSL changes.
  --target-dir <path>          Deployment directory to run health check against (defaults to current dir if it contains docker-compose.yml; otherwise computed from --base-dir + --repo)

  -h, --help                 Show this help
EOF
}

# ---------------------- Arg parsing --------------------------
while [ "${#:-0}" -gt 0 ]; do
  case "$1" in
    --reset-auth) RESET_AUTH=1; shift ;;
    --reinstall)  FULL_REINSTALL=1; shift ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --yes) ASSUME_YES=1; shift ;;
    --ufw-auto-allow) UFW_AUTO_ALLOW=1; shift ;;
    --ufw-skip) UFW_SKIP=1; shift ;;
    --health-check-only) HEALTH_CHECK_ONLY=1; shift ;;
    --health-check-json) HEALTH_CHECK_JSON=1; shift ;;
    --target-dir) TARGET_DIR="${2:-}"; shift 2 ;;


    --app) APP_ID="${2:-}"; shift 2 ;;
    --base-dir) BASE_DIR="${2:-}"; shift 2 ;;
    --domain) APP_DOMAIN="${2:-}"; shift 2 ;;
    --repo) REPO_SSH="${2:-}"; shift 2 ;;
    --branch) BRANCH="${2:-}"; shift 2 ;;

    --tls) TLS_PROVIDER_NAME="${2:-}"; shift 2 ;;
    --cf-cert) CF_CERT_PATH="${2:-}"; shift 2 ;;
    --cf-key) CF_KEY_PATH="${2:-}"; shift 2 ;;

    --basic-user) BASIC_AUTH_USER="${2:-}"; shift 2 ;;
    --basic-pass) BASIC_AUTH_PASS="${2:-}"; shift 2 ;;
    --gen-pass) BASIC_AUTH_GEN="yes"; shift ;;
    --no-gen-pass) BASIC_AUTH_GEN="no"; shift ;;

    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1 (use --help)";;
  esac
done

# ---------------------- Privilege ----------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "sudo not found (install sudo or run as root)."
  SUDO="sudo"
fi

# ---------------------- Helpers ------------------------------
print_header() {
  cat <<'EOF'
============================================================
 ReyadWeb SaaS Installer (Ubuntu + Cloudflare friendly)
============================================================
EOF
  if [ "$NON_INTERACTIVE" -eq 1 ]; then warn "Mode: NON-INTERACTIVE"; fi
  if [ "$RESET_AUTH" -eq 1 ]; then warn "Mode: RESET AUTH (regenerate Basic Auth credentials)."; fi
  if [ "$FULL_REINSTALL" -eq 1 ]; then warn "Mode: FULL REINSTALL (remove containers + volumes)."; fi
}

require_ubuntu() {
  # shellcheck disable=SC1091
  . /etc/os-release || die "Unable to read /etc/os-release"
  [ "${ID:-}" = "ubuntu" ] || die "Ubuntu only. Detected: ${ID:-unknown}"
  info "OS check OK: Ubuntu (${VERSION_ID:-unknown})"
}

check_min_resources() {
  local cpu mem_kb mem_mb disk_kb disk_gb
  cpu="$(nproc 2>/dev/null || echo 0)"
  mem_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)"
  mem_mb="$((mem_kb / 1024))"
  local disk_target="${BASE_DIR:-/}"
  disk_kb="$(df -Pk "$disk_target" 2>/dev/null | awk 'NR==2{print $4}' || echo 0)"
  disk_gb="$((disk_kb / 1024 / 1024))"

  info "Resource check: CPU=${cpu} cores | RAM=${mem_mb} MB | Free disk on ${disk_target}=${disk_gb} GB"

  local ok=1
  if [ "$cpu" -lt "$MIN_CPU_CORES" ]; then warn "CPU below recommended minimum (${MIN_CPU_CORES})."; ok=0; fi
  if [ "$mem_mb" -lt "$MIN_RAM_MB" ]; then warn "RAM below recommended minimum (${MIN_RAM_MB} MB)."; ok=0; fi
  if [ "$disk_gb" -lt "$MIN_DISK_GB" ]; then warn "Disk below recommended minimum (${MIN_DISK_GB} GB)."; ok=0; fi

  if [ "$ok" -eq 0 ] && [ "$ASSUME_YES" -eq 0 ]; then
    echo ""
    read -r -p "Proceed anyway? [y/N]: " PROCEED
    case "${PROCEED:-N}" in y|Y|yes|YES) info "Proceeding."; ;; *) die "Aborting (insufficient resources)."; ;; esac
  fi

  if [ "$ok" -eq 0 ] && [ "$ASSUME_YES" -eq 1 ]; then
    warn "Proceeding despite low resources because --yes was provided."
  fi
}

ensure_prereqs() {
  info "Installing prerequisites (git, curl, ca-certificates, openssh-client, python3, openssl)..."
  $SUDO apt-get update -y
  $SUDO apt-get install -y git curl ca-certificates openssh-client python3 openssl
}

install_docker_if_missing() {
  if command -v docker >/dev/null 2>&1; then
    info "Docker already installed."
    return 0
  fi

  info "Installing Docker Engine + Compose plugin (official Docker repo)..."
  $SUDO apt-get update -y
  $SUDO apt-get install -y ca-certificates curl gnupg

  $SUDO install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  $SUDO chmod a+r /etc/apt/keyrings/docker.gpg

  # shellcheck disable=SC1091
  . /etc/os-release
  UBUNTU_CODENAME="${VERSION_CODENAME:-}"
  [ -n "$UBUNTU_CODENAME" ] || die "Could not detect Ubuntu codename."

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME} stable" \
    | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null

  $SUDO apt-get update -y
  $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  info "Docker installed."
  warn "Installer will use sudo docker if needed (no docker group changes)."
}

docker_cmd() {
  if docker ps >/dev/null 2>&1; then
    echo "docker"
  else
    echo "$SUDO docker"
  fi
}

ensure_ufw_ports() {
  if [ "$UFW_SKIP" -eq 1 ]; then
    info "UFW step skipped by --ufw-skip."
    return 0
  fi

  if ! command -v ufw >/dev/null 2>&1; then
    info "UFW not installed; skipping firewall checks."
    return 0
  fi
  local status
  status="$($SUDO ufw status 2>/dev/null | head -n 1 || true)"
  if echo "$status" | grep -qi "Status: active"; then
    info "UFW is active."
    if [ "$UFW_AUTO_ALLOW" -eq 1 ] || [ "$NON_INTERACTIVE" -eq 1 ]; then
      info "Auto-allowing ports 22/80/443..."
      $SUDO ufw allow 22/tcp >/dev/null || true
      $SUDO ufw allow 80/tcp >/dev/null || true
      $SUDO ufw allow 443/tcp >/dev/null || true
      info "UFW rules applied (22, 80, 443)."
      return 0
    fi

    echo ""
    read -r -p "Allow SSH (22) + HTTP (80) + HTTPS (443) through UFW? [Y/n]: " ans
    ans="${ans:-Y}"
    case "$ans" in
      y|Y|yes|YES)
        $SUDO ufw allow 22/tcp >/dev/null || true
        $SUDO ufw allow 80/tcp >/dev/null || true
        $SUDO ufw allow 443/tcp >/dev/null || true
        info "UFW rules applied (22, 80, 443)."
        ;;
      *)
        warn "Skipped opening ports. TLS/cert issuance may fail and Cloudflare may show 525/522."
        ;;
    esac
  else
    info "UFW is not active; skipping firewall port rules."
  fi
}


normalize_tls_mode() {
  # Backwards-compatible: --tls cloudflare can mean either:
  #  - cloudflare-le (no cert/key files; Cloudflare proxied, origin uses Let's Encrypt)
  #  - cloudflare-origin (cert/key provided; origin uses Cloudflare Origin CA)
  case "$TLS_PROVIDER_NAME" in
    cloudflare)
      if [[ -n "$CF_CERT_PATH" || -n "$CF_KEY_PATH" ]]; then
        TLS_PROVIDER_NAME="cloudflare-origin"
      else
        TLS_PROVIDER_NAME="cloudflare-le"
      fi
      ;;
    cloudflare-le|cloudflare-origin|cloudflare-internal|letsencrypt)
      ;;
    *)
      # Leave validation to validate_inputs()
      ;;
  esac
}


validate_inputs() {
  [ "$APP_ID" = "1" ] || die "Invalid --app (only 1 supported for now)."
  BASE_DIR="${BASE_DIR:-$DEFAULT_BASE_DIR}"
  REPO_SSH="${REPO_SSH:-$DEFAULT_REPO_SSH}"
  BRANCH="${BRANCH:-$DEFAULT_BRANCH}"

  normalize_tls_mode

  case "$TLS_PROVIDER_NAME" in
    letsencrypt|cloudflare-le|cloudflare-origin|cloudflare-internal) ;;
    *) die "Invalid --tls value: $TLS_PROVIDER_NAME (use letsencrypt|cloudflare|cloudflare-le|cloudflare-origin|cloudflare-internal)";;
  esac

  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    [ -n "$APP_DOMAIN" ] || die "--domain is required in non-interactive mode."
    if [ "$TLS_PROVIDER_NAME" = "cloudflare-origin" ]; then
      [ -n "$CF_CERT_PATH" ] || die "--cf-cert is required for --tls cloudflare-origin."
      [ -n "$CF_KEY_PATH" ] || die "--cf-key is required for --tls cloudflare-origin."
      [ -f "$CF_CERT_PATH" ] || die "Cloudflare cert not found: $CF_CERT_PATH"
      [ -f "$CF_KEY_PATH" ] || die "Cloudflare key not found: $CF_KEY_PATH"
    fi
  fi
}

menu_select_app() {
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    info "App selected: $APP_ID"
    return 0
  fi

  echo ""
  echo "Available SaaS apps:"
  echo "  1) AutoFix Pro (saastest)"
  echo "     - Docker Compose: Postgres + Node API + Caddy + Basic Auth"
  echo ""
  read -r -p "Select an app [1]: " APP_ID_IN
  APP_ID="${APP_ID_IN:-$DEFAULT_APP_ID}"
  [ "$APP_ID" = "1" ] || die "Invalid selection: $APP_ID"
}

prompt_inputs_interactive() {
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    return 0
  fi

  echo ""
  read -r -p "Base install directory [${DEFAULT_BASE_DIR}]: " BASE_DIR_IN
  BASE_DIR="${BASE_DIR_IN:-$DEFAULT_BASE_DIR}"

  echo ""
  read -r -p "Domain (FQDN) for this install (e.g. portal.example.com): " APP_DOMAIN
  [ -n "${APP_DOMAIN}" ] || die "Domain is required."

  echo ""

  echo "TLS mode:"
  echo "  1) Let's Encrypt (direct DNS / no proxy)"
  echo "  2) Cloudflare proxied (orange cloud) + Let's Encrypt on origin (no cert files)"
  echo "  3) Cloudflare Origin CA (Full (strict) with Origin cert/key files)"
  echo "  4) Cloudflare proxied + internal TLS (bootstrap; no cert files; Cloudflare SSL = Full)"
  echo ""
  read -r -p "Select TLS mode [1]: " TLS_PROVIDER
  TLS_PROVIDER="${TLS_PROVIDER:-1}"
  case "$TLS_PROVIDER" in
  1) TLS_PROVIDER_NAME="letsencrypt" ;;
  2) TLS_PROVIDER_NAME="cloudflare-le" ;;
  3) TLS_PROVIDER_NAME="cloudflare-origin" ;;
  4) TLS_PROVIDER_NAME="cloudflare-internal" ;;
  *) die "Invalid TLS mode selection: $TLS_PROVIDER" ;;
  esac
info "TLS mode selected: $TLS_PROVIDER_NAME"

  echo ""
  read -r -p "Private repo SSH URL [${DEFAULT_REPO_SSH}]: " REPO_IN
  REPO_SSH="${REPO_IN:-$DEFAULT_REPO_SSH}"

  echo ""
  read -r -p "Branch (blank = default) [${DEFAULT_BRANCH}]: " BRANCH_IN
  BRANCH="${BRANCH_IN:-$DEFAULT_BRANCH}"

  if [ "$TLS_PROVIDER_NAME" = "cloudflare-origin" ]; then
    echo ""
    echo "Cloudflare Origin CA requires a certificate + private key from Cloudflare."
    echo "Create it in Cloudflare dashboard: SSL/TLS → Origin Server → Create Certificate"
    echo "Include hostname: ${APP_DOMAIN}"
    echo ""
    read -r -p "Path to Origin certificate (.crt/.pem) (blank to skip): " CF_CERT_PATH
    if [ -z "${CF_CERT_PATH:-}" ]; then
      warn "No Origin cert provided. Switching to Cloudflare proxied + Let's Encrypt (cloudflare-le)."
      TLS_PROVIDER_NAME="cloudflare-le"
    else
      read -r -p "Path to Origin private key (.key): " CF_KEY_PATH
      [ -n "${CF_KEY_PATH:-}" ] || die "Key path is required when a cert path is provided."
      [ -f "$CF_CERT_PATH" ] || die "Cert file not found: $CF_CERT_PATH"
      [ -f "$CF_KEY_PATH" ] || die "Key file not found: $CF_KEY_PATH"
    fi
  fi
}

ensure_ssh_key() {
  local key_path="$1"

  mkdir -p "$HOME/.ssh"
  chmod 700 "$HOME/.ssh"

  if [ -f "$key_path" ]; then
    info "Using existing SSH key: $key_path"
  else
    info "Generating SSH deploy key: $key_path"
    ssh-keygen -t ed25519 -f "$key_path" -N "" -C "saas-installer@$(hostname)" >/dev/null
    chmod 600 "$key_path"
  fi

  ssh -o StrictHostKeyChecking=accept-new -i "$key_path" -T git@github.com >/dev/null 2>&1 || true

  echo ""
  info "If private repo clone fails, add this public key as a Deploy Key (read-only recommended):"
  echo "------------------------------------------------------------"
  cat "${key_path}.pub"
  echo "------------------------------------------------------------"
  echo ""
}

git_ssh() {
  local key_path="$1"
  echo "ssh -i \\"$key_path\\" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
}

clone_or_update_repo() {
  local repo_ssh="$1"
  local key_path="$2"
  local target_dir="$3"
  local branch="$4"

  local GIT_SSH_COMMAND
  GIT_SSH_COMMAND="$(git_ssh "$key_path")"
  export GIT_SSH_COMMAND

  mkdir -p "$(dirname "$target_dir")"

  if [ -d "$target_dir/.git" ]; then
    info "Repo already exists. Updating..."
    git -C "$target_dir" remote set-url origin "$repo_ssh" >/dev/null 2>&1 || true
    git -C "$target_dir" fetch --all --prune
    if [ -n "$branch" ]; then
      git -C "$target_dir" checkout "$branch"
      git -C "$target_dir" pull --ff-only origin "$branch"
    else
      git -C "$target_dir" pull --ff-only
    fi
  else
    info "Cloning repo into: $target_dir"
    if [ -n "$branch" ]; then
      git clone --branch "$branch" "$repo_ssh" "$target_dir"
    else
      git clone "$repo_ssh" "$target_dir"
    fi
  fi
}

retry_or_fail_clone() {
  local repo_ssh="$1"
  local key_path="$2"
  local target_dir="$3"
  local branch="$4"

  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    set +e
    clone_or_update_repo "$repo_ssh" "$key_path" "$target_dir" "$branch"
    local rc=$?
    set -e
    if [ "$rc" -ne 0 ]; then
      warn "Clone failed (likely missing Deploy Key access)."
      warn "Add the printed public key to GitHub Deploy Keys, then rerun."
      exit 2
    fi
    return 0
  fi

  while true; do
    set +e
    clone_or_update_repo "$repo_ssh" "$key_path" "$target_dir" "$branch"
    local rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
      return 0
    fi

    warn "Clone failed (likely missing Deploy Key access)."
    echo ""
    echo "Next step:"
    echo "  1) Copy the public key shown above"
    echo "  2) GitHub → private repo → Settings → Deploy keys → Add deploy key"
    echo "  3) Read-only recommended"
    echo "  4) Then press ENTER to retry"
    echo ""
    read -r -p "Press ENTER to retry (or Ctrl+C to quit): " _
  done
}

generate_password_safe() {
  # Avoid characters that break shell history expansion or copy/paste in terminals (notably '!').
  tr -dc 'A-Za-z0-9@#%_=+.-' < /dev/urandom | head -c 28
}

write_caddy_env() {
  local domain="$1"
  local user="$2"
  local hash="$3"

  # Escape $ so Docker Compose doesn't treat bcrypt as env interpolation.
  local hash_escaped="${hash//$/\\$\\$}"

  cat > caddy.env <<EOF
APP_DOMAIN=${domain}
BASIC_AUTH_USER=${user}
BASIC_AUTH_HASH=${hash_escaped}
EOF
  chmod 600 caddy.env || true
}

confirm_saved_password() {
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    return 0
  fi
  echo ""
  echo "IMPORTANT: This password will NOT be shown again."
  echo "Copy it now into a password manager / secure note."
  echo ""
  while true; do
    read -r -p "Type SAVED to continue: " ack
    if [ "${ack:-}" = "SAVED" ]; then return 0; fi
    echo "Please type exactly: SAVED"
  done
}

ensure_cloudflare_origin_certs() {
  local cert_dir="$1"
  mkdir -p "$cert_dir"
  chmod 700 "$cert_dir" || true

  cp -f "$CF_CERT_PATH" "${cert_dir}/origin.crt"
  cp -f "$CF_KEY_PATH"  "${cert_dir}/origin.key"
  chmod 600 "${cert_dir}/origin.key" || true
  chmod 644 "${cert_dir}/origin.crt" || true

  info "Origin certs staged at: ${cert_dir}/origin.crt and ${cert_dir}/origin.key"
}

write_cloudflare_override_files() {
  # Creates:
  # - docker-compose.override.yml (mount certs + override caddyfile)
  # - caddy/Caddyfile.cloudflare (adds manual tls directive)
  local base_caddyfile=""
  if [ -f "./caddy/Caddyfile" ]; then base_caddyfile="./caddy/Caddyfile"; fi
  if [ -z "$base_caddyfile" ] && [ -f "./Caddyfile" ]; then base_caddyfile="./Caddyfile"; fi
  [ -n "$base_caddyfile" ] || die "Could not find a Caddyfile in repo (expected ./caddy/Caddyfile or ./Caddyfile)."

  mkdir -p ./caddy

  python3 - "$base_caddyfile" "./caddy/Caddyfile.cloudflare" <<'PY'
import pathlib, sys
base = pathlib.Path(sys.argv[1])
dst  = pathlib.Path(sys.argv[2])
text = base.read_text(encoding="utf-8")
lines = text.splitlines()
out, inserted = [], False
for i, line in enumerate(lines):
    out.append(line)
    if not inserted and "{" in line and not line.strip().startswith("#") and i <= 3:
        out.append("    tls /certs/origin.crt /certs/origin.key")
        inserted = True
if not inserted:
    raise SystemExit("Failed to auto-insert tls directive into Caddyfile.")
dst.write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")
PY

  cat > docker-compose.override.yml <<'EOF'
services:
  caddy:
    volumes:
      - ./certs:/certs:ro
      - ./caddy/Caddyfile.cloudflare:/etc/caddy/Caddyfile:ro
EOF
  info "Wrote Cloudflare override files: docker-compose.override.yml and caddy/Caddyfile.cloudflare"
  warn "NOTE: Cloudflare Origin CA cert is not browser-trusted. Keep Cloudflare proxy ON, and restrict origin access if possible."
}

write_cloudflare_le_override_files() {
  # Creates:
  # - docker-compose.override.yml (override caddyfile only)
  # - caddy/Caddyfile.cloudflare-le (modernizes auth + disables TLS-ALPN to avoid Cloudflare ALPN issues)
  local base_caddyfile=""
  if [ -f "./caddy/Caddyfile" ]; then base_caddyfile="./caddy/Caddyfile"; fi
  if [ -z "$base_caddyfile" ] && [ -f "./Caddyfile" ]; then base_caddyfile="./Caddyfile"; fi
  [ -n "$base_caddyfile" ] || die "Could not find a Caddyfile in repo (expected ./caddy/Caddyfile or ./Caddyfile)."

  mkdir -p ./caddy

  CADDYFILE_PATH="$base_caddyfile" OUT_CADDYFILE="./caddy/Caddyfile.cloudflare-le" python3 - <<'PY'
import os, pathlib
base = pathlib.Path(os.environ["CADDYFILE_PATH"]).read_text(encoding="utf-8")

# Replace deprecated basicauth with basic_auth (Caddy v2.7+)
base = base.replace('basicauth {', 'basic_auth {')

lines = base.splitlines()
out = []
inserted = False

for i, line in enumerate(lines):
    out.append(line)
    # Insert tls issuer block very early (within the first few lines of the site block)
    if not inserted and "{" in line and not line.strip().startswith("#") and i <= 3:
        out.append("    tls {")
        out.append("      issuer acme {")
        out.append("        disable_tlsalpn_challenge")
        out.append("      }")
        out.append("    }")
        inserted = True

if not inserted:
    raise SystemExit("Failed to auto-insert tls issuer block into Caddyfile.")

pathlib.Path(os.environ["OUT_CADDYFILE"]).write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")
PY

  cat > docker-compose.override.yml <<'EOF'
services:
  caddy:
    volumes:
      - ./caddy/Caddyfile.cloudflare-le:/etc/caddy/Caddyfile:ro
EOF
}


write_cloudflare_internal_override_files() {
  # Creates:
  # - docker-compose.override.yml (override caddyfile only)
  # - caddy/Caddyfile.cloudflare-internal (adds: tls internal)
  local base_caddyfile=""
  if [ -f "./caddy/Caddyfile" ]; then base_caddyfile="./caddy/Caddyfile"; fi
  if [ -z "$base_caddyfile" ] && [ -f "./Caddyfile" ]; then base_caddyfile="./Caddyfile"; fi
  [ -n "$base_caddyfile" ] || die "Could not find a Caddyfile in repo (expected ./caddy/Caddyfile or ./Caddyfile)."

  mkdir -p ./caddy

  CADDYFILE_PATH="$base_caddyfile" OUT_CADDYFILE="./caddy/Caddyfile.cloudflare-internal" python3 - <<'PY'
import os, pathlib
base = pathlib.Path(os.environ["CADDYFILE_PATH"]).read_text(encoding="utf-8")

# Replace deprecated basicauth with basic_auth (Caddy v2.7+)
base = base.replace('basicauth {', 'basic_auth {')

lines = base.splitlines()
out = []
inserted = False
for i, line in enumerate(lines):
    out.append(line)
    if not inserted and "{" in line and not line.strip().startswith("#") and i <= 3:
        out.append("    tls internal")
        inserted = True

if not inserted:
    raise SystemExit("Failed to auto-insert tls internal into Caddyfile.")

pathlib.Path(os.environ["OUT_CADDYFILE"]).write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")
PY

  cat > docker-compose.override.yml <<'EOF'
services:
  caddy:
    volumes:
      - ./caddy/Caddyfile.cloudflare-internal:/etc/caddy/Caddyfile:ro
EOF

  info "Wrote Cloudflare internal TLS override files: docker-compose.override.yml and caddy/Caddyfile.cloudflare-internal"
  warn "NOTE: This uses a self-signed cert from Caddy (tls internal). In Cloudflare, set SSL/TLS mode to Full (not strict)."
}



json_escape() {
  # Minimal JSON string escaper (no external deps)
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\r'/\\r}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}


emit_healthcheck_json() {
  # Args:
  #  1  domain
  #  2  tls_mode
  #  3  caddy_line
  #  4  has_listeners_json (true/false/null)
  #  5  a_records_json (JSON array)
  #  6  is_cf_json (true/false/null)
  #  7  https_code_json (int/null)
  #  8  result_code (stable enum string)
  #  9  recommendation
  # 10  pub_ip_json (quoted string/null)
  # 11  dns_matches_json (true/false/null)
  # 12  name of next_steps array var
  # 13  name of notes array var
  # 14  json_target ("stdout" or file path)
  # 15  json_stdout (1/0)

  local domain="$1"

  local tls_mode="$2"
  local caddy_line="$3"
  local has_listeners_json="$4"
  local a_records_json="$5"
  local is_cf_json="$6"
  local https_code_json="$7"
  local result_code="$8"
  local recommendation="$9"
  local pub_ip_json="${10}"
  local dns_matches_json="${11}"
  local next_steps_arr_name="${12}"
  local notes_arr_name="${13}"
  local target="${14}"
  local json_stdout="${15}"

  # Indirectly reference arrays
  eval "local -a _next_steps=(\"\${${next_steps_arr_name}[@]}\")"
  eval "local -a _notes=(\"\${${notes_arr_name}[@]}\")"

  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

  local caddy_json="null"
  if [ -n "$caddy_line" ]; then
    caddy_json="\"$(json_escape "$caddy_line")\""
  fi

  local rec_json="\"$(json_escape "$recommendation")\""

  # next_steps -> JSON array
  local ns_json="[]"
  if [ "${#_next_steps[@]}" -gt 0 ]; then
    ns_json="["
    local it
    for it in "${_next_steps[@]}"; do
      ns_json="${ns_json}\"$(json_escape "$it")\","
    done
    ns_json="${ns_json%,}]"
  fi

  # notes -> JSON array
  local notes_json="[]"
  if [ "${#_notes[@]}" -gt 0 ]; then
    notes_json="["
    local it2
    for it2 in "${_notes[@]}"; do
      notes_json="${notes_json}\"$(json_escape "$it2")\","
    done
    notes_json="${notes_json%,}]"
  fi

  # default public ip json if still null-like
  if [ -z "$pub_ip_json" ] || [ "$pub_ip_json" = "null" ]; then
    pub_ip_json="null"
  fi

  local json
  json="{"
  json="${json}\"timestamp\":\"$(json_escape "$ts")\","
  json="${json}\"domain\":\"$(json_escape "$domain")\","
  json="${json}\"tls_mode\":\"$(json_escape "$tls_mode")\","
  json="${json}\"cloudflare_detected\":${is_cf_json},"
  json="${json}\"https_status\":${https_code_json},"
  json="${json}\"result_code\":\"$(json_escape "$result_code")\","
  json="${json}\"recommendation\":${rec_json},"
  json="${json}\"dns_a_records\":${a_records_json},"
  json="${json}\"public_ip\":${pub_ip_json},"
  json="${json}\"dns_matches_public_ip\":${dns_matches_json},"
  json="${json}\"compose_caddy\":${caddy_json},"
  json="${json}\"listeners_80_443\":${has_listeners_json},"
  json="${json}\"next_steps\":${ns_json},"
  json="${json}\"notes\":${notes_json}"
  json="${json}}"

  if [ "$target" = "stdout" ]; then
    # stdout must be JSON only
    echo "$json"
  else
    printf '%s\n' "$json" > "$target"
    if [ "$json_stdout" -eq 1 ]; then
      echo "==> Health check JSON written to: $target" >&2
    else
      info "Health check JSON written to: $target"
    fi
  fi
}



cloudflare_health_check() {
  local DC="$1"
  local domain="$2"
  local tls_mode="$3"
  local json_target="${4:-}"   # "stdout" for clean JSON; otherwise treated as file path
  local json_stdout=0

  # JSON is primarily intended for --health-check-only (stdout). During full deploy, we write JSON to a file.
  if [ "${HEALTH_CHECK_JSON:-0}" -eq 1 ] && [ "$json_target" = "stdout" ]; then
    json_stdout=1
  fi

  # Print helpers (keep stdout clean for JSON mode)
  hc_print() { if [ "$json_stdout" -eq 1 ]; then echo "$*" >&2; else echo "$*"; fi; }
  hc_info()  { if [ "$json_stdout" -eq 1 ]; then echo "==> $*" >&2; else info "$*"; fi; }

  local next_steps=()
  local notes=()

  local caddy_line=""
  local has_listeners_json="null"

  local a_records=""
  local a_records_json="[]"

  local hdr=""
  local is_cf=0
  local is_cf_json="null"

  local code="000"
  local https_code_json="null"
  local result_code="unknown"
  local recommendation=""

  local pub_ip=""
  local pub_ip_json="null"
  local dns_matches_json="null"

  local body_file=""
  body_file="$(mktemp /tmp/saas_cf_body.XXXXXX)"

  hc_print ""
  hc_info "Cloudflare / HTTPS health check (post-deploy)..."

  # Compose status (best-effort)
  if $DC compose ps >/dev/null 2>&1; then
    caddy_line="$($DC compose ps 2>/dev/null | awk 'NR>1 && $1 ~ /caddy/ {print $0}' | head -n1 || true)"
    if [ -n "$caddy_line" ]; then
      hc_print "Compose: ${caddy_line}"
    fi
  fi

  # Local port check (best-effort)
  if command -v ss >/dev/null 2>&1; then
    if ss -lnt 2>/dev/null | grep -qE ':(80|443)\s'; then
      has_listeners_json="true"
    else
      has_listeners_json="false"
      warn "No listeners detected on 80/443 (stack may still be starting)."
      notes+=("No listeners detected on 80/443 (stack may still be starting).")
    fi
  fi

  # DNS resolution (A records)
  if command -v dig >/dev/null 2>&1; then
    a_records="$(dig +short A "$domain" 2>/dev/null | tr '\n' ' ' | xargs || true)"
  elif command -v getent >/dev/null 2>&1; then
    a_records="$(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' | xargs || true)"
  elif command -v nslookup >/dev/null 2>&1; then
    a_records="$(nslookup -type=A "$domain" 2>/dev/null | awk '/Address: /{print $2}' | tail -n +2 | tr '\n' ' ' | xargs || true)"
  fi

  # Convert A records -> JSON array (best-effort)
  if [ -n "$a_records" ]; then
    a_records_json="["
    local ip
    for ip in $a_records; do
      a_records_json="${a_records_json}\"$(json_escape "$ip")\","
    done
    a_records_json="${a_records_json%,}]"
  fi

  if [ -z "$a_records" ]; then
    warn "DNS A record for ${domain} did not resolve from this server."
    hc_print "Next step:"
    hc_print "  - Create/verify an A record for ${domain} to your server public IP."
    hc_print "  - If you just changed DNS, wait a few minutes and retry."
    next_steps+=("Create/verify an A record for ${domain} to your server public IP.")
    next_steps+=("If you just changed DNS, wait a few minutes and retry.")
    result_code="dns_no_resolution"
    recommendation="DNS did not resolve from this server."
    # Emit JSON if requested
    if [ "${HEALTH_CHECK_JSON:-0}" -eq 1 ]; then
      emit_healthcheck_json "$domain" "$tls_mode" "$caddy_line" "$has_listeners_json" "$a_records_json" "$is_cf_json" "$https_code_json" "$result_code" "$recommendation" "$pub_ip_json" "$dns_matches_json" next_steps notes "$json_target" "$json_stdout"
    fi
    rm -f "$body_file" 2>/dev/null || true
    return 0
  fi
  hc_info "DNS A records: ${a_records}"

  if ! command -v curl >/dev/null 2>&1; then
    warn "curl not found; skipping HTTP checks."
    notes+=("curl not found; skipping HTTP checks.")
    result_code="curl_missing"
    recommendation="curl not found; skipped HTTP checks."
    if [ "${HEALTH_CHECK_JSON:-0}" -eq 1 ]; then
      emit_healthcheck_json "$domain" "$tls_mode" "$caddy_line" "$has_listeners_json" "$a_records_json" "$is_cf_json" "$https_code_json" "$result_code" "$recommendation" "$pub_ip_json" "$dns_matches_json" next_steps notes "$json_target" "$json_stdout"
    fi
    rm -f "$body_file" 2>/dev/null || true
    return 0
  fi

  # Detect whether Cloudflare is in front (best-effort)
  hdr="$(curl -sI --max-time 15 "https://${domain}" 2>/dev/null || true)"
  echo "$hdr" | grep -qiE '^server: cloudflare' && is_cf=1
  echo "$hdr" | grep -qiE '^cf-ray:' && is_cf=1
  if [ "$is_cf" -eq 1 ]; then is_cf_json="true"; else is_cf_json="false"; fi

  # Fetch status code
  code="$(curl -s -o "$body_file" -w "%{http_code}" --max-time 20 "https://${domain}" 2>/dev/null || echo "000")"
  if echo "$code" | grep -qE '^[0-9]{3}$'; then
    https_code_json="$code"
  else
    https_code_json="null"
  fi

  if [ "$is_cf" -eq 1 ]; then
    hc_info "Edge: Cloudflare detected (proxied)."
  else
    warn "Edge: Cloudflare not detected (DNS-only / direct)."
  fi
  hc_info "HTTPS status: ${code}"

  # If internal/origin cert modes require proxy, warn if not proxied
  if [ "$is_cf" -eq 0 ]; then
    if [ "$tls_mode" = "cloudflare-internal" ] || [ "$tls_mode" = "cloudflare-origin" ]; then
      warn "This TLS mode expects Cloudflare proxy (orange cloud) to be ON."
      hc_print "Next step:"
      hc_print "  - In Cloudflare DNS, enable proxy (orange cloud) for ${domain}, OR"
      hc_print "  - Rerun installer with --tls letsencrypt (or --tls cloudflare-le) for browser-trusted origin certs."
      next_steps+=("In Cloudflare DNS, enable proxy (orange cloud) for ${domain}.")
      next_steps+=("Or rerun installer with --tls letsencrypt (or --tls cloudflare-le) for browser-trusted origin certs.")
      result_code="proxy_expected_off"
      recommendation="Cloudflare proxy expected but not detected."
      if [ "${HEALTH_CHECK_JSON:-0}" -eq 1 ]; then
        emit_healthcheck_json "$domain" "$tls_mode" "$caddy_line" "$has_listeners_json" "$a_records_json" "$is_cf_json" "$https_code_json" "$result_code" "$recommendation" "$pub_ip_json" "$dns_matches_json" next_steps notes "$json_target" "$json_stdout"
      fi
      rm -f "$body_file" 2>/dev/null || true
      return 0
    fi
  fi

  case "$code" in
  200|301|302|307|308)
    result_code="ok"
    recommendation="OK: ${domain} is reachable over HTTPS."
    ;;
  525)
    result_code="cf_525_ssl_handshake_failed"
    recommendation="Cloudflare 525: SSL handshake failed between Cloudflare and origin."
    ;;
  526)
    result_code="cf_526_invalid_origin_cert"
    recommendation="Cloudflare 526: Invalid SSL certificate at origin (usually Full (strict) + untrusted cert)."
    ;;
  522)
    result_code="cf_522_origin_timeout"
    recommendation="Cloudflare 522: Cloudflare cannot reach your origin (timeout)."
    ;;
  523)
    result_code="cf_523_origin_unreachable"
    recommendation="Cloudflare 523: Cloudflare cannot reach your origin (unreachable)."
    ;;
  524)
    result_code="cf_524_origin_timeout"
    recommendation="Cloudflare 524: Cloudflare connection to origin timed out."
    ;;
  000)
    result_code="request_failed"
    recommendation="Request failed from this server (DNS/timeout/TLS)."
    ;;
  *)
    result_code="unexpected_status"
    recommendation="Unexpected HTTPS status code: ${code}"
    ;;
esac

  hc_print ""
  hc_print "Result: ${recommendation}"
  hc_print ""

  # Targeted "do this next" guidance
  case "$code" in
    200|301|302|307|308)
      hc_print "Next step: none (looks good)."
      ;;
    525)
      if [ "$tls_mode" = "cloudflare-internal" ]; then
        hc_print "Next step:"
        hc_print "  - In Cloudflare: SSL/TLS mode must be Full (not strict) for 'tls internal'."
        next_steps+=("In Cloudflare: SSL/TLS mode must be Full (not strict) for 'tls internal'.")
      elif [ "$tls_mode" = "cloudflare-le" ]; then
        hc_print "Next step:"
        hc_print "  - If this is the first run, cert issuance may still be in progress."
        hc_print "  - Temporarily set Cloudflare SSL/TLS to Full (not strict) OR set DNS record to 'DNS only', rerun installer, then switch back to Full (strict)."
        next_steps+=("If this is the first run, cert issuance may still be in progress.")
        next_steps+=("Temporarily set Cloudflare SSL/TLS to Full (not strict) OR set DNS record to 'DNS only', rerun installer, then switch back to Full (strict).")
      else
        hc_print "Next step:"
        hc_print "  - Ensure the Caddy container is running and ports 80/443 are open."
        hc_print "  - Verify the origin cert/key are correct (Origin CA) and mounted to /certs."
        hc_print "  - Cloudflare should be Full (strict) when using Origin CA."
        next_steps+=("Ensure the Caddy container is running and ports 80/443 are open.")
        next_steps+=("Verify the origin cert/key are correct (Origin CA) and mounted to /certs.")
        next_steps+=("Cloudflare should be Full (strict) when using Origin CA.")
      fi
      ;;
    526)
      if [ "$tls_mode" = "cloudflare-internal" ]; then
        hc_print "Next step:"
        hc_print "  - Switch Cloudflare SSL/TLS mode to Full (not strict), OR rerun with --tls cloudflare-le / --tls cloudflare-origin."
        next_steps+=("Switch Cloudflare SSL/TLS mode to Full (not strict), OR rerun with --tls cloudflare-le / --tls cloudflare-origin.")
      elif [ "$tls_mode" = "cloudflare-origin" ]; then
        hc_print "Next step:"
        hc_print "  - Confirm Origin CA cert/key paths are correct and staged to ./certs/origin.*"
        hc_print "  - Keep proxy ON (orange cloud) and set Cloudflare SSL/TLS mode to Full (strict)."
        next_steps+=("Confirm Origin CA cert/key paths are correct and staged to ./certs/origin.*")
        next_steps+=("Keep proxy ON (orange cloud) and set Cloudflare SSL/TLS mode to Full (strict).")
      else
        hc_print "Next step:"
        hc_print "  - Ensure origin has a valid public cert (Let's Encrypt), then use Full (strict)."
        next_steps+=("Ensure origin has a valid public cert (Let's Encrypt), then use Full (strict).")
      fi
      ;;
    522|523|524)
      hc_print "Next step:"
      hc_print "  - Confirm inbound 80/443 are allowed (UFW / cloud firewall)."
      hc_print "  - Confirm Caddy is listening on 80/443 (docker compose ps, docker logs caddy)."
      hc_print "  - Confirm ${domain} DNS record is correct, and (if proxied) that the origin IP is correct."
      next_steps+=("Confirm inbound 80/443 are allowed (UFW / cloud firewall).")
      next_steps+=("Confirm Caddy is listening on 80/443 (docker compose ps, docker logs caddy).")
      next_steps+=("Confirm ${domain} DNS record is correct, and (if proxied) that the origin IP is correct.")
      ;;
    000)
      hc_print "Next step:"
      hc_print "  - If DNS was just changed, wait a few minutes and retry."
      hc_print "  - Confirm your server can resolve DNS and reach the internet."
      hc_print "  - If using Cloudflare internal/origin, ensure proxy is ON (orange cloud)."
      next_steps+=("If DNS was just changed, wait a few minutes and retry.")
      next_steps+=("Confirm your server can resolve DNS and reach the internet.")
      next_steps+=("If using Cloudflare internal/origin, ensure proxy is ON (orange cloud).")
      ;;
    *)
      hc_print "Next step:"
      hc_print "  - Check: docker compose ps, docker logs caddy, and Cloudflare SSL/TLS settings."
      next_steps+=("Check: docker compose ps, docker logs caddy, and Cloudflare SSL/TLS settings.")
      ;;
  esac

  # If not Cloudflare proxied, and we can fetch public IP, compare
  if [ "$is_cf" -eq 0 ]; then
    pub_ip="$(curl -s --max-time 8 https://api.ipify.org 2>/dev/null || true)"
    if [ -n "$pub_ip" ]; then
      pub_ip_json="\"$(json_escape "$pub_ip")\""
      hc_print ""
      if echo "$a_records" | grep -q "$pub_ip"; then
        dns_matches_json="true"
        hc_info "DNS appears to point to this server (${pub_ip})."
      else
        dns_matches_json="false"
        if [ "$result_code" = "ok" ] || [ "$result_code" = "request_failed" ] || [ "$result_code" = "unexpected_status" ]; then
          result_code="direct_dns_mismatch_public_ip"
        fi
        warn "DNS A record does not match this server public IP (${pub_ip})."
        hc_print "Next step:"
        hc_print "  - Update the A record for ${domain} to ${pub_ip} (or to the correct origin IP)."
        next_steps+=("Update the A record for ${domain} to ${pub_ip} (or to the correct origin IP).")
      fi
    fi
  fi

  # Emit JSON (stdout for --health-check-only; file for full deploy)
  if [ "${HEALTH_CHECK_JSON:-0}" -eq 1 ]; then
    # default file path if not explicit
    if [ -z "$json_target" ]; then
      json_target="saas-healthcheck.json"
    fi
    emit_healthcheck_json "$domain" "$tls_mode" "$caddy_line" "$has_listeners_json" "$a_records_json" "$is_cf_json" "$https_code_json" "$result_code" "$recommendation" "$pub_ip_json" "$dns_matches_json" next_steps notes "$json_target" "$json_stdout"
  fi

  rm -f "$body_file" 2>/dev/null || true
}



ensure_basic_auth() {
  local DC="$1"
  local domain="$2"

  if [ "$RESET_AUTH" -eq 1 ]; then
    info "Reset-auth requested: removing existing caddy.env (if any)."
    rm -f caddy.env || true
  fi

  if [ -f "caddy.env" ] && [ "$NON_INTERACTIVE" -eq 0 ] && [ "$RESET_AUTH" -eq 0 ]; then
    echo ""
    read -r -p "caddy.env exists. Reuse existing Basic Auth credentials? [Y/n]: " reuse
    reuse="${reuse:-Y}"
    case "$reuse" in
      y|Y|yes|YES)
        # Update APP_DOMAIN inside caddy.env (idempotent)
        python3 - <<PY
import pathlib
p = pathlib.Path("caddy.env")
lines = p.read_text(encoding="utf-8").splitlines()
out = []
found = False
for line in lines:
    if line.startswith("APP_DOMAIN="):
        out.append("APP_DOMAIN=%s")
        found = True
    else:
        out.append(line)
if not found:
    out.insert(0, "APP_DOMAIN=%s")
p.write_text("\\n".join(out).rstrip("\\n") + "\\n", encoding="utf-8")
PY
        sed -i "s|APP_DOMAIN=%s|APP_DOMAIN=${domain}|g" caddy.env
        info "Reused caddy.env and updated APP_DOMAIN=${domain}"
        return 0
        ;;
      *)
        info "Will regenerate Basic Auth credentials."
        rm -f caddy.env || true
        ;;
    esac
  fi

  if [ -f "caddy.env" ] && [ "$NON_INTERACTIVE" -eq 1 ] && [ "$RESET_AUTH" -eq 0 ]; then
    # Non-interactive: keep existing credentials, but ensure domain matches
    python3 - <<PY
import pathlib
p = pathlib.Path("caddy.env")
lines = p.read_text(encoding="utf-8").splitlines()
out = []
found = False
for line in lines:
    if line.startswith("APP_DOMAIN="):
        out.append("APP_DOMAIN=%s")
        found = True
    else:
        out.append(line)
if not found:
    out.insert(0, "APP_DOMAIN=%s")
p.write_text("\\n".join(out).rstrip("\\n") + "\\n", encoding="utf-8")
PY
    sed -i "s|APP_DOMAIN=%s|APP_DOMAIN=${domain}|g" caddy.env
    info "Found existing caddy.env; updated APP_DOMAIN=${domain}"
    return 0
  fi

  BASIC_AUTH_USER="${BASIC_AUTH_USER:-admin}"

  # Decide on password source
  if [ -n "$BASIC_AUTH_PASS" ]; then
    info "Using provided --basic-pass (plaintext will be hashed locally; not stored)."
  else
    if [ "$BASIC_AUTH_GEN" = "no" ]; then
      if [ "$NON_INTERACTIVE" -eq 1 ]; then
        die "--no-gen-pass requires --basic-pass in non-interactive mode."
      fi
      echo ""
      echo "Enter Basic Auth password (plaintext). It will be hashed locally; only the hash is stored."
      read -r -s -p "Basic Auth password: " BASIC_AUTH_PASS
      echo ""
      [ -n "${BASIC_AUTH_PASS}" ] || die "Password is required."
    else
      # auto or yes => generate unless interactive user says no
      if [ "$NON_INTERACTIVE" -eq 0 ] && [ "$BASIC_AUTH_GEN" = "auto" ]; then
        echo ""
        read -r -p "Generate a strong random Basic Auth password now? [Y/n]: " gen
        gen="${gen:-Y}"
        if [[ ! "$gen" =~ ^(y|Y|yes|YES)$ ]]; then
          echo ""
          echo "Enter Basic Auth password (plaintext). It will be hashed locally; only the hash is stored."
          read -r -s -p "Basic Auth password: " BASIC_AUTH_PASS
          echo ""
          [ -n "${BASIC_AUTH_PASS}" ] || die "Password is required."
        else
          BASIC_AUTH_PASS="$(generate_password_safe)"
        fi
      else
        BASIC_AUTH_PASS="$(generate_password_safe)"
      fi

      if [ -n "$BASIC_AUTH_PASS" ]; then
        echo ""
        info "Basic Auth password (save it now):"
        echo "------------------------------------------------------------"
        echo "$BASIC_AUTH_PASS"
        echo "------------------------------------------------------------"
        confirm_saved_password
        echo ""
        echo "Tip (curl test):"
        echo "  curl -I -u '${BASIC_AUTH_USER}:${BASIC_AUTH_PASS}' https://${domain} | head -n 1"
        echo ""
        if [ "$NON_INTERACTIVE" -eq 1 ]; then
          warn "Non-interactive mode: password printed once above. If lost, rerun with --reset-auth."
        fi
      fi
    fi
  fi

  info "Generating BASIC_AUTH_HASH via Caddy..."
  local BASIC_AUTH_HASH
  BASIC_AUTH_HASH="$($DC run --rm caddy:2-alpine caddy hash-password --plaintext "$BASIC_AUTH_PASS")"
  write_caddy_env "$domain" "$BASIC_AUTH_USER" "$BASIC_AUTH_HASH"
  info "Wrote ./caddy.env (hash safely escaped)."
}

deploy_app1() {
  local target_dir="$1"
  local domain="$2"
  cd "$target_dir"

  local DC
  DC="$(docker_cmd)"

  if [ "$FULL_REINSTALL" -eq 1 ]; then
    warn "FULL REINSTALL will delete Docker volumes (including Postgres data)."
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
      [ "$ASSUME_YES" -eq 1 ] || die "--reinstall in non-interactive requires --yes"
    else
      read -r -p "Type DELETE to confirm full reinstall: " confirm
      [ "${confirm:-}" = "DELETE" ] || die "Full reinstall cancelled."
    fi

    info "Stopping and removing stack + volumes..."
    $DC compose down -v || true
    rm -f caddy.env docker-compose.override.yml ./caddy/Caddyfile.cloudflare || true
    rm -rf ./certs || true
    info "Full reinstall cleanup complete."
  fi

  if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    cp .env.example .env
    info "Created .env from .env.example"
  fi

  # TLS mode config
  rm -f docker-compose.override.yml ./caddy/Caddyfile.cloudflare ./caddy/Caddyfile.cloudflare-le 2>/dev/null || true

  case "$TLS_PROVIDER_NAME" in
    letsencrypt)
      # no override file needed
      ;;
    cloudflare-le)
      write_cloudflare_le_override_files
      ;;
    cloudflare-internal)
      write_cloudflare_internal_override_files
      ;;
    cloudflare-origin)
      ensure_cloudflare_origin_certs "./certs"
      write_cloudflare_override_files
      ;;
    *)
      die "Unexpected TLS mode: $TLS_PROVIDER_NAME"
      ;;
  esac

  ensure_basic_auth "$DC" "$domain"

  info "Starting stack (docker compose up -d --build)..."
  $DC compose up -d --build


  # Post-deploy check for Cloudflare modes (detect 525/526/522 and common misconfig)
  case "$TLS_PROVIDER_NAME" in
    cloudflare-*)
      if [ "${HEALTH_CHECK_JSON:-0}" -eq 1 ]; then
        local hc_json_file
        hc_json_file="${target_dir}/saas-healthcheck.json"
        cloudflare_health_check "$DC" "$domain" "$TLS_PROVIDER_NAME" "$hc_json_file"
      else
        cloudflare_health_check "$DC" "$domain" "$TLS_PROVIDER_NAME"
      fi
      ;;
  esac

  echo ""
  info "Deployment finished."
  echo "URL: https://${domain}"
  echo ""
  echo "If you lose access:"
  echo "  Re-run installer with: --reset-auth (keeps DB/data)"
  echo "  Example: curl -fsSL <installer-url> | bash -s -- --reset-auth"
  echo ""
  if [ "$TLS_PROVIDER_NAME" = "cloudflare-origin" ]; then
    echo "Cloudflare Origin CA notes:"
    echo "  - Set Cloudflare SSL/TLS mode to: Full (strict)"
    echo "  - Keep the DNS record proxied (orange cloud)"
    echo "  - Restrict origin access if possible (UFW allow only Cloudflare IP ranges, or use Tunnel)"
    echo "  - If you rotate the Origin cert/key, update ./certs/origin.* then restart caddy"
    echo ""
  elif [ "$TLS_PROVIDER_NAME" = "cloudflare-internal" ]; then
    echo "Cloudflare proxied + internal TLS (bootstrap) notes:"
    echo "  - Set Cloudflare SSL/TLS mode to: Full (not strict)"
    echo "  - Keep the DNS record proxied (orange cloud)"
    echo "  - Origin uses Caddy \"tls internal\" (self-signed). Do NOT access origin directly in a browser"
    echo "  - When ready, rerun installer with --tls cloudflare-le or --tls cloudflare-origin to tighten SSL"
    echo ""
  elif [ "$TLS_PROVIDER_NAME" = "cloudflare-le" ]; then
    echo "Cloudflare proxied + Let's Encrypt notes:"
    echo "  - The origin gets a public Let's Encrypt cert; Cloudflare can stay proxied (orange cloud)"
    echo "  - After cert issuance, set Cloudflare SSL/TLS mode to: Full (strict)"
    echo "  - If you see HTTP 525 during first issuance, temporarily set Cloudflare SSL/TLS to Full (not strict) or set DNS to 'DNS only' then retry"
    echo ""
  else
    echo "Let's Encrypt mode notes:"
    echo "  - Ensure ports 80 and 443 are reachable from the internet"
    echo "  - If Cloudflare proxy is ON and cert issuance fails, temporarily set DNS to 'DNS only' then retry"
    echo ""
  fi
}

run_health_check_only() {
  local dir domain tls_mode DC

  dir="$(detect_target_dir_for_healthcheck)"

  [ -n "$dir" ] || die "Unable to determine target dir for health check."
  [ -d "$dir" ] || die "Target dir not found: $dir (use --target-dir <path> or run from the deploy directory)."

  domain="$(detect_domain_from_deploy_dir "$dir" || true)"
  [ -n "$domain" ] || die "Unable to detect domain. Provide --domain <fqdn> or ensure ${dir}/caddy.env contains APP_DOMAIN=..."

  tls_mode="$(detect_tls_mode_from_deploy_dir "$dir" || true)"
  [ -n "$tls_mode" ] || tls_mode="unknown"

  cd "$dir"

  DC="$(docker_cmd)"

  info "Health-check-only mode: dir=${dir} domain=${domain} tls=${tls_mode}"
  if [ "${HEALTH_CHECK_JSON:-0}" -eq 1 ]; then
    cloudflare_health_check "$DC" "$domain" "$tls_mode" "stdout"
  else
    cloudflare_health_check "$DC" "$domain" "$tls_mode"
  fi


  echo ""
  info "Health check complete."
}

detect_target_dir_for_healthcheck() {
  # 1) explicit --target-dir
  if [ -n "${TARGET_DIR:-}" ]; then
    echo "$TARGET_DIR"
    return 0
  fi

  # 2) current directory looks like a deployment dir
  if [ -f "./docker-compose.yml" ] || [ -f "./compose.yml" ] || [ -f "./docker-compose.yaml" ] || [ -f "./compose.yaml" ]; then
    echo "$PWD"
    return 0
  fi

  # 3) computed from --base-dir + --repo (same rule used for deploy)
  local base repo repo_name
  base="${BASE_DIR:-$DEFAULT_BASE_DIR}"
  repo="${REPO_SSH:-$DEFAULT_REPO_SSH}"
  repo_name="$(basename "$repo")"
  repo_name="${repo_name%.git}"
  echo "${base}/${repo_name}"
}

strip_quotes() {
  # Strips surrounding single/double quotes if present.
  local s="$1"
  s="${s%\"}"; s="${s#\"}"
  s="${s%\'}"; s="${s#\'}"
  echo "$s"
}

detect_domain_from_deploy_dir() {
  local dir="$1"

  # 1) explicit --domain
  if [ -n "${APP_DOMAIN:-}" ]; then
    echo "$APP_DOMAIN"
    return 0
  fi

  # 2) env files created by this installer
  local f val
  for f in "$dir/caddy.env" "$dir/.env" "$dir/docker/.env" "$dir/env/.env" "$dir/.env.production" "$dir/.env.local"; do
    if [ -f "$f" ]; then
      val="$(grep -E '^(APP_DOMAIN|DOMAIN|HOSTNAME)=' "$f" 2>/dev/null | head -n1 | cut -d= -f2- | xargs || true)"
      val="$(strip_quotes "$val")"
      if [ -n "$val" ]; then
        echo "$val"
        return 0
      fi
    fi
  done

  # 3) try to infer from Caddyfile host block
  local cf host
  for cf in "$dir/caddy/Caddyfile.cloudflare-internal" "$dir/caddy/Caddyfile" "$dir/Caddyfile"; do
    if [ -f "$cf" ]; then
      host="$(awk 'NF && $1 !~ /^#/ {print $1; exit}' "$cf" 2>/dev/null || true)"
      host="${host%\{}"
      host="${host%%,*}"
      host="${host%%:80}"
      host="${host%%:443}"
      host="$(strip_quotes "$host")"
      if echo "$host" | grep -q '\.'; then
        echo "$host"
        return 0
      fi
    fi
  done

  return 1
}

detect_tls_mode_from_deploy_dir() {
  local dir="$1"

  # Respect explicit --tls if user provided it (even in health-check-only mode).
  if [ -n "${TLS_PROVIDER_NAME:-}" ] && [ "$TLS_PROVIDER_NAME" != "letsencrypt" ]; then
    echo "$TLS_PROVIDER_NAME"
    return 0
  fi

  # Strong signals
  if [ -f "$dir/docker-compose.override.yml" ] && grep -q 'Caddyfile.cloudflare-internal' "$dir/docker-compose.override.yml" 2>/dev/null; then
    echo "cloudflare-internal"
    return 0
  fi

  if [ -f "$dir/certs/origin.crt" ] || [ -f "$dir/certs/origin.pem" ] || [ -f "$dir/certs/origin.key" ]; then
    echo "cloudflare-origin"
    return 0
  fi

  # Heuristic: Caddyfile uses tls internal
  if [ -f "$dir/caddy/Caddyfile" ] && grep -qE '^[[:space:]]*tls[[:space:]]+internal\b' "$dir/caddy/Caddyfile" 2>/dev/null; then
    echo "cloudflare-internal"
    return 0
  fi

  echo "unknown"
}


main() {
  print_header
  require_ubuntu

  if [ "$HEALTH_CHECK_ONLY" -eq 1 ]; then
    run_health_check_only
    return 0
  fi

  menu_select_app
  prompt_inputs_interactive
  validate_inputs

  check_min_resources
  ensure_prereqs
  install_docker_if_missing
  ensure_ufw_ports

  local repo_name target_dir key_path
  repo_name="$(basename "$REPO_SSH")"
  repo_name="${repo_name%.git}"
  target_dir="${BASE_DIR}/${repo_name}"
  key_path="$HOME/.ssh/saas_installer_${repo_name}_ed25519"

  ensure_ssh_key "$key_path"
  retry_or_fail_clone "$REPO_SSH" "$key_path" "$target_dir" "$BRANCH"

  deploy_app1 "$target_dir" "$APP_DOMAIN"
}

main
