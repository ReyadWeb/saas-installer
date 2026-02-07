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
#   --tls letsencrypt    (default, Caddy Automatic HTTPS)
#   --tls cloudflare     (Cloudflare Origin CA cert/key)
#
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

APP_ID="$DEFAULT_APP_ID"
BASE_DIR=""
APP_DOMAIN=""
TLS_PROVIDER_NAME="letsencrypt"  # letsencrypt | cloudflare
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
      --tls cloudflare \
      --cf-cert /path/to/origin.crt \
      --cf-key  /path/to/origin.key \
      --yes

Flags:
  --app <id>                 App selection (default: 1)
  --base-dir <path>          Install base dir (default: ~/apps)
  --domain <fqdn>            Required in non-interactive mode
  --repo <ssh_url>           Private repo SSH URL (default: ReyadWeb/saastest)
  --branch <name>            Git branch (optional)

  --tls <letsencrypt|cloudflare>  TLS provider (default: letsencrypt)
  --cf-cert <path>           Cloudflare Origin cert path (required if --tls cloudflare in non-interactive)
  --cf-key <path>            Cloudflare Origin key path  (required if --tls cloudflare in non-interactive)

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

validate_inputs() {
  [ "$APP_ID" = "1" ] || die "Invalid --app (only 1 supported for now)."
  BASE_DIR="${BASE_DIR:-$DEFAULT_BASE_DIR}"
  REPO_SSH="${REPO_SSH:-$DEFAULT_REPO_SSH}"
  BRANCH="${BRANCH:-$DEFAULT_BRANCH}"

  case "$TLS_PROVIDER_NAME" in
    letsencrypt|cloudflare) ;;
    *) die "Invalid --tls value: $TLS_PROVIDER_NAME (use letsencrypt|cloudflare)";;
  esac

  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    [ -n "$APP_DOMAIN" ] || die "--domain is required in non-interactive mode."
    if [ "$TLS_PROVIDER_NAME" = "cloudflare" ]; then
      [ -n "$CF_CERT_PATH" ] || die "--cf-cert is required for --tls cloudflare."
      [ -n "$CF_KEY_PATH" ] || die "--cf-key is required for --tls cloudflare."
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
  echo "TLS provider:"
  echo "  1) Let's Encrypt (Caddy automatic HTTPS)  [recommended default]"
  echo "  2) Cloudflare Origin CA (manual cert/key)"
  echo ""
  read -r -p "Select TLS provider [1]: " TLS_PROVIDER
  TLS_PROVIDER="${TLS_PROVIDER:-1}"
  case "$TLS_PROVIDER" in
    1) TLS_PROVIDER_NAME="letsencrypt" ;;
    2) TLS_PROVIDER_NAME="cloudflare" ;;
    *) die "Invalid TLS provider selection: $TLS_PROVIDER" ;;
  esac
  info "TLS provider selected: $TLS_PROVIDER_NAME"

  echo ""
  read -r -p "Private repo SSH URL [${DEFAULT_REPO_SSH}]: " REPO_IN
  REPO_SSH="${REPO_IN:-$DEFAULT_REPO_SSH}"

  echo ""
  read -r -p "Branch (blank = default) [${DEFAULT_BRANCH}]: " BRANCH_IN
  BRANCH="${BRANCH_IN:-$DEFAULT_BRANCH}"

  if [ "$TLS_PROVIDER_NAME" = "cloudflare" ]; then
    echo ""
    echo "Cloudflare Origin CA requires a certificate + private key from Cloudflare."
    echo "Create it in Cloudflare dashboard: SSL/TLS → Origin Server → Create Certificate"
    echo "Include hostname: ${APP_DOMAIN}"
    echo ""
    read -r -p "Path to Origin certificate (.crt/.pem): " CF_CERT_PATH
    read -r -p "Path to Origin private key (.key): " CF_KEY_PATH
    [ -f "$CF_CERT_PATH" ] || die "Cert file not found: $CF_CERT_PATH"
    [ -f "$CF_KEY_PATH" ] || die "Key file not found: $CF_KEY_PATH"
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

  # TLS provider config
  if [ "$TLS_PROVIDER_NAME" = "cloudflare" ]; then
    ensure_cloudflare_origin_certs "./certs"
    write_cloudflare_override_files
  else
    rm -f docker-compose.override.yml ./caddy/Caddyfile.cloudflare || true
  fi

  ensure_basic_auth "$DC" "$domain"

  info "Starting stack (docker compose up -d --build)..."
  $DC compose up -d --build

  echo ""
  info "Deployment finished."
  echo "URL: https://${domain}"
  echo ""
  echo "If you lose access:"
  echo "  Re-run installer with: --reset-auth (keeps DB/data)"
  echo "  Example: curl -fsSL <installer-url> | bash -s -- --reset-auth"
  echo ""
  if [ "$TLS_PROVIDER_NAME" = "cloudflare" ]; then
    echo "Cloudflare mode notes:"
    echo "  - Set Cloudflare SSL/TLS mode to: Full (strict)"
    echo "  - Keep the DNS record proxied (orange cloud)"
    echo "  - Restrict origin access if possible (UFW allow only Cloudflare IP ranges, or use Tunnel)"
    echo ""
  else
    echo "Let's Encrypt mode notes:"
    echo "  - Ensure ports 80 and 443 are reachable from the internet"
    echo "  - If Cloudflare proxy is ON and cert issuance fails, temporarily set DNS to 'DNS only' then retry"
    echo ""
  fi
}

main() {
  print_header
  require_ubuntu

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
