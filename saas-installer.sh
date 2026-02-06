#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# ReyadWeb SaaS Installer (public bootstrap)
# - Runs on fresh Ubuntu
# - Uses SSH deploy keys to clone private SaaS repos
# - Prompts for domain + basic auth (for SaaS #1)
#
# Preflight included:
#   1) Assert Ubuntu
#   2) UFW detection + prompt to open ports (22/80/443)
#   3) Resource checks (CPU/RAM/Disk) + optional swap creation
#   4) Port conflict detection (80/443)
# ============================================================

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "WARN: $*" >&2; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "sudo not found (install sudo or run as root)."
  SUDO="sudo"
fi

DEFAULT_BASE_DIR="$HOME/apps"
DEFAULT_APP_ID="1"

APP1_NAME="AutoFix Pro (saastest)"
APP1_REPO_DEFAULT="git@github.com:ReyadWeb/saastest.git"
APP1_DESC="Docker Compose stack: Postgres + Node API + Caddy HTTPS + Basic Auth"

MIN_CPU=1
REC_CPU=2
MIN_RAM_MB=1500
REC_RAM_MB=2000
MIN_DISK_MB=10000
REC_DISK_MB=20000
SWAP_MB=2048

print_header() {
  cat <<'EOF'
============================================================
 ReyadWeb SaaS Installer (Ubuntu + Cloudflare friendly)
============================================================
EOF
}

assert_ubuntu() {
  [ -f /etc/os-release ] || die "Cannot detect OS (missing /etc/os-release). This installer supports Ubuntu."
  # shellcheck disable=SC1091
  . /etc/os-release
  if [ "${ID:-}" != "ubuntu" ]; then
    die "Unsupported OS: ${PRETTY_NAME:-unknown}. This installer supports Ubuntu only."
  fi
  info "OS OK: ${PRETTY_NAME:-Ubuntu}"
}

prompt_yes_no() {
  local q="$1"
  local def="${2:-Y}"
  local ans=""
  if [ "$def" = "Y" ]; then
    read -r -p "$q [Y/n]: " ans
    ans="${ans:-Y}"
  else
    read -r -p "$q [y/N]: " ans
    ans="${ans:-N}"
  fi
  case "$ans" in
    Y|y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

get_mem_mb()  { awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0; }
get_swap_mb() { awk '/^SwapTotal:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0; }

check_resources() {
  local cpu mem_mb disk_mb
  cpu="$(nproc 2>/dev/null || echo 0)"
  mem_mb="$(get_mem_mb)"
  disk_mb="$(df -Pm / | awk 'NR==2 {print $4}' 2>/dev/null || echo 0)"

  info "Resource check: CPU=${cpu}, RAM=${mem_mb}MB, FreeDisk=${disk_mb}MB"

  [ "$cpu" -ge "$MIN_CPU" ] || die "CPU too low: ${cpu}. Minimum is ${MIN_CPU}."
  [ "$mem_mb" -ge "$MIN_RAM_MB" ] || die "RAM too low: ${mem_mb}MB. Minimum is ${MIN_RAM_MB}MB."
  [ "$disk_mb" -ge "$MIN_DISK_MB" ] || die "Disk too low: ${disk_mb}MB free. Minimum is ${MIN_DISK_MB}MB free."

  [ "$cpu" -ge "$REC_CPU" ] || warn "CPU below recommended (${cpu} < ${REC_CPU}). Builds may be slower."
  [ "$mem_mb" -ge "$REC_RAM_MB" ] || warn "RAM below recommended (${mem_mb}MB < ${REC_RAM_MB}MB)."
  [ "$disk_mb" -ge "$REC_DISK_MB" ] || warn "Disk below recommended (${disk_mb}MB < ${REC_DISK_MB}MB)."
}

ensure_swap_if_needed() {
  local mem_mb swap_mb
  mem_mb="$(get_mem_mb)"
  swap_mb="$(get_swap_mb)"

  if [ "$mem_mb" -ge "$REC_RAM_MB" ] || [ "$swap_mb" -gt 0 ]; then
    return 0
  fi

  warn "Low RAM detected: ${mem_mb}MB and no swap. Recommended is ${REC_RAM_MB}MB+."
  if prompt_yes_no "Create a ${SWAP_MB}MB swapfile to reduce build failures?" "Y"; then
    info "Creating swapfile (/swapfile) ..."
    if $SUDO fallocate -l "${SWAP_MB}M" /swapfile 2>/dev/null; then
      :
    else
      $SUDO dd if=/dev/zero of=/swapfile bs=1M count="${SWAP_MB}" status=progress
    fi
    $SUDO chmod 600 /swapfile
    $SUDO mkswap /swapfile >/dev/null
    $SUDO swapon /swapfile
    if ! grep -qE '^\s*/swapfile\s' /etc/fstab; then
      echo "/swapfile none swap sw 0 0" | $SUDO tee -a /etc/fstab >/dev/null
    fi
    info "Swap enabled."
  else
    warn "Continuing without swap."
  fi
}

check_ufw_and_open_ports() {
  if ! command -v ufw >/dev/null 2>&1; then
    info "UFW not installed (ok)."
    return 0
  fi

  local status
  status="$($SUDO ufw status 2>/dev/null | head -n1 || true)"
  if echo "$status" | grep -qi "Status: active"; then
    warn "UFW is active."
    if prompt_yes_no "Open required ports (22/80/443) in UFW?" "Y"; then
      $SUDO ufw allow 22/tcp || true
      $SUDO ufw allow 80/tcp || true
      $SUDO ufw allow 443/tcp || true
      $SUDO ufw reload || true
      info "UFW rules applied."
    else
      warn "Ports may be blocked by UFW. Ensure 22/80/443 are allowed."
    fi
  else
    info "UFW installed but not active."
  fi
}

check_port_conflicts() {
  if ss -ltnp 2>/dev/null | grep -Eq ':(80|443)\s'; then
    warn "Port 80/443 is already in use (can block Caddy)."
    ss -ltnp 2>/dev/null | grep -E ':(80|443)\s' || true

    if prompt_yes_no "Attempt to stop common conflicting services (apache2/nginx)?" "Y"; then
      for svc in apache2 nginx; do
        if command -v systemctl >/dev/null 2>&1; then
          if $SUDO systemctl is-active --quiet "$svc" 2>/dev/null; then
            info "Stopping $svc ..."
            $SUDO systemctl stop "$svc" || true
            $SUDO systemctl disable "$svc" || true
          fi
        fi
      done
    fi
  else
    info "Ports 80/443 are free."
  fi
}

menu_select_app() {
  echo ""
  echo "Available SaaS apps:"
  echo "  1) ${APP1_NAME}"
  echo "     - ${APP1_DESC}"
  echo ""
  read -r -p "Select an app [1]: " APP_ID
  APP_ID="${APP_ID:-$DEFAULT_APP_ID}"
  case "$APP_ID" in
    1) ;;
    *) die "Invalid selection: $APP_ID" ;;
  esac
}

ensure_prereqs() {
  info "Installing prerequisites (git, curl, ca-certificates, openssh-client, python3)..."
  $SUDO apt-get update -y
  $SUDO apt-get install -y git curl ca-certificates openssh-client python3
}

install_docker_if_missing() {
  if command -v docker >/dev/null 2>&1; then
    info "Docker already installed."
    return 0
  fi

  info "Installing Docker Engine + Compose plugin..."
  $SUDO apt-get update -y
  $SUDO apt-get install -y ca-certificates curl gnupg

  $SUDO install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  $SUDO chmod a+r /etc/apt/keyrings/docker.gpg

  # shellcheck disable=SC1091
  . /etc/os-release
  UBUNTU_CODENAME="${VERSION_CODENAME:-}"
  [ -n "$UBUNTU_CODENAME" ] || die "Could not detect Ubuntu codename."

  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME} stable"     | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null

  $SUDO apt-get update -y
  $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  if [ "$(id -u)" -ne 0 ]; then
    $SUDO usermod -aG docker "$USER" || true
    warn "You may need to log out/in to use docker without sudo. Installer will use sudo if needed."
  fi
}

docker_cmd() {
  if docker ps >/dev/null 2>&1; then echo "docker"; else echo "$SUDO docker"; fi
}

ensure_ssh_key() {
  local key_path="$1"
  mkdir -p "$HOME/.ssh"
  chmod 700 "$HOME/.ssh"

  if [ ! -f "$key_path" ]; then
    info "Generating SSH deploy key: $key_path"
    ssh-keygen -t ed25519 -f "$key_path" -N "" -C "saas-installer@$(hostname)" >/dev/null
    chmod 600 "$key_path"
  else
    info "Using existing SSH key: $key_path"
  fi

  ssh -o StrictHostKeyChecking=accept-new -i "$key_path" -T git@github.com >/dev/null 2>&1 || true

  echo ""
  info "Add this public key as a Deploy Key (read-only recommended) to the PRIVATE repo:"
  echo "------------------------------------------------------------"
  cat "${key_path}.pub"
  echo "------------------------------------------------------------"
  echo ""
}

git_ssh() {
  local key_path="$1"
  echo "ssh -i "$key_path" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
}

clone_repo() {
  local repo_ssh="$1"
  local key_path="$2"
  local target_dir="$3"
  local branch="$4"

  export GIT_SSH_COMMAND
  GIT_SSH_COMMAND="$(git_ssh "$key_path")"

  mkdir -p "$(dirname "$target_dir")"

  if [ -d "$target_dir/.git" ]; then
    info "Repo exists. Updating..."
    git -C "$target_dir" fetch --all --prune
    if [ -n "$branch" ]; then
      git -C "$target_dir" checkout "$branch"
      git -C "$target_dir" pull --ff-only origin "$branch"
    else
      git -C "$target_dir" pull --ff-only
    fi
  else
    info "Cloning into: $target_dir"
    if [ -n "$branch" ]; then
      git clone --branch "$branch" "$repo_ssh" "$target_dir"
    else
      git clone "$repo_ssh" "$target_dir"
    fi
  fi
}

retry_clone_until_ok() {
  local repo_ssh="$1"
  local key_path="$2"
  local target_dir="$3"
  local branch="$4"

  while true; do
    set +e
    clone_repo "$repo_ssh" "$key_path" "$target_dir" "$branch"
    local rc=$?
    set -e
    [ "$rc" -eq 0 ] && return 0

    warn "Clone failed (missing deploy key access is common)."
    echo "Add the printed public key to GitHub Deploy Keys, then press ENTER to retry."
    read -r -p "Press ENTER to retry (or Ctrl+C to quit): " _
  done
}

deploy_saastest() {
  local target_dir="$1"
  local domain="$2"

  cd "$target_dir"

  if [ ! -f ".env" ] && [ -f ".env.example" ]; then
    cp .env.example .env
    info "Created .env from .env.example"
  fi

  echo ""
  read -r -p "Basic Auth username [admin]: " BASIC_AUTH_USER
  BASIC_AUTH_USER="${BASIC_AUTH_USER:-admin}"

  echo ""
  echo "Enter Basic Auth password (plaintext). It will be hashed locally."
  read -r -s -p "Basic Auth password: " BASIC_AUTH_PASS
  echo ""
  [ -n "${BASIC_AUTH_PASS}" ] || die "Password is required."

  local DC
  DC="$(docker_cmd)"

  info "Generating BASIC_AUTH_HASH via Caddy..."
  BASIC_AUTH_HASH="$($DC run --rm caddy:2-alpine caddy hash-password --plaintext "$BASIC_AUTH_PASS")"

  cat > caddy.env <<EOF
APP_DOMAIN=${domain}
BASIC_AUTH_USER=${BASIC_AUTH_USER}
BASIC_AUTH_HASH=${BASIC_AUTH_HASH}
EOF
  chmod 600 caddy.env || true

  # Patch compose to load caddy.env via env_file (avoids $ interpolation warnings)
  if grep -q 'BASIC_AUTH_HASH: \${BASIC_AUTH_HASH' docker-compose.yml 2>/dev/null; then
    info "Patching docker-compose.yml to load caddy.env via env_file..."
    python3 - <<'PY'
import re, pathlib
p = pathlib.Path("docker-compose.yml")
s = p.read_text(encoding="utf-8")

m = re.search(r"(^\s*caddy:\s*
(?:^\s{4}.*
)*)", s, re.M)
if not m:
    raise SystemExit("Could not locate 'caddy' service block.")

block = m.group(1)
block2 = re.sub(r"^\s{4}environment:\s*
(?:^\s{6,}.*
)+", "", block, flags=re.M)

lines = block2.splitlines(True)
for i, line in enumerate(lines):
    if re.match(r"^\s*caddy:\s*$", line):
        lines.insert(i+1, "    env_file:
      - ./caddy.env
    environment:
      - APP_DOMAIN
      - BASIC_AUTH_USER
      - BASIC_AUTH_HASH
")
        break

block3 = "".join(lines)
p.write_text(s[:m.start(1)] + block3 + s[m.end(1):], encoding="utf-8")
PY
  fi

  info "Starting stack..."
  $DC compose up -d --build

  echo ""
  info "Deployment finished: https://${domain}"
}

main() {
  print_header
  assert_ubuntu
  check_resources
  ensure_swap_if_needed
  check_ufw_and_open_ports
  check_port_conflicts

  menu_select_app

  echo ""
  read -r -p "Base install directory [${DEFAULT_BASE_DIR}]: " BASE_DIR
  BASE_DIR="${BASE_DIR:-$DEFAULT_BASE_DIR}"

  echo ""
  read -r -p "Domain (FQDN) for this install (e.g. portal.example.com): " APP_DOMAIN
  [ -n "${APP_DOMAIN}" ] || die "Domain is required."

  ensure_prereqs
  install_docker_if_missing

  echo ""
  read -r -p "Private repo SSH URL [${APP1_REPO_DEFAULT}]: " REPO_SSH
  REPO_SSH="${REPO_SSH:-$APP1_REPO_DEFAULT}"

  echo ""
  read -r -p "Branch (blank = default): " BRANCH

  REPO_NAME="$(basename "$REPO_SSH")"
  REPO_NAME="${REPO_NAME%.git}"
  TARGET_DIR="${BASE_DIR}/${REPO_NAME}"
  KEY_PATH="$HOME/.ssh/saas_installer_${REPO_NAME}_ed25519"

  ensure_ssh_key "$KEY_PATH"
  retry_clone_until_ok "$REPO_SSH" "$KEY_PATH" "$TARGET_DIR" "$BRANCH"

  deploy_saastest "$TARGET_DIR" "$APP_DOMAIN"
}

main "$@"
