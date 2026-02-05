#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# ReyadWeb SaaS Installer (public bootstrap)
# - Runs on fresh Ubuntu
# - Uses SSH deploy keys to clone private SaaS repos
# - Prompts for domain + basic auth (for SaaS #1)
# ============================================================

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "WARN: $*" >&2; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }

# --- sudo handling
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "sudo not found (install sudo or run as root)."
  SUDO="sudo"
fi

# --- defaults
DEFAULT_BASE_DIR="$HOME/apps"
DEFAULT_BRANCH=""
DEFAULT_APP_ID="1"

# --- SaaS catalog (extend later)
APP1_NAME="AutoFix Pro (saastest)"
APP1_REPO_DEFAULT="git@github.com:ReyadWeb/saastest.git"
APP1_DESC="Docker Compose stack: Postgres + Node API + Caddy HTTPS + Basic Auth"

print_header() {
  cat <<'EOF'
============================================================
 ReyadWeb SaaS Installer (Ubuntu + Cloudflare friendly)
============================================================
EOF
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

prompt_inputs_common() {
  echo ""
  read -r -p "Base install directory [${DEFAULT_BASE_DIR}]: " BASE_DIR
  BASE_DIR="${BASE_DIR:-$DEFAULT_BASE_DIR}"

  echo ""
  read -r -p "Domain (FQDN) for this install (e.g. portal.example.com): " APP_DOMAIN
  [ -n "${APP_DOMAIN}" ] || die "Domain is required."
  if ! echo "$APP_DOMAIN" | grep -Eq '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'; then
    warn "Domain doesn't look like a typical FQDN. Continuing anyway: $APP_DOMAIN"
  fi

  echo ""
  read -r -p "Branch (blank = default) [${DEFAULT_BRANCH}]: " BRANCH
  BRANCH="${BRANCH:-$DEFAULT_BRANCH}"
}

ensure_prereqs() {
  info "Installing prerequisites (git, curl, ca-certificates, openssh-client)..."
  $SUDO apt-get update -y
  $SUDO apt-get install -y git curl ca-certificates openssh-client
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

  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME} stable" \
    | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null

  $SUDO apt-get update -y
  $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

  # Allow current user to run docker without sudo (after re-login)
  if [ "$(id -u)" -ne 0 ]; then
    $SUDO usermod -aG docker "$USER" || true
  fi

  info "Docker installed."
  if [ "$(id -u)" -ne 0 ]; then
    warn "You may need to log out/in to use docker without sudo. This installer will use sudo if needed."
  fi
}

docker_cmd() {
  # Prefer docker without sudo if it works
  if docker ps >/dev/null 2>&1; then
    echo "docker"
  else
    echo "$SUDO docker"
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

  # Ensure known_hosts has GitHub (accept-new)
  ssh -o StrictHostKeyChecking=accept-new -i "$key_path" -T git@github.com >/dev/null 2>&1 || true

  echo ""
  info "If the private repo clone fails, add this public key as a Deploy Key (read-only recommended):"
  echo "------------------------------------------------------------"
  cat "${key_path}.pub"
  echo "------------------------------------------------------------"
  echo ""
}

git_ssh() {
  local key_path="$1"
  echo "ssh -i \"$key_path\" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
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

retry_clone_until_ok() {
  local repo_ssh="$1"
  local key_path="$2"
  local target_dir="$3"
  local branch="$4"

  while true; do
    set +e
    clone_or_update_repo "$repo_ssh" "$key_path" "$target_dir" "$branch"
    local rc=$?
    set -e
    if [ "$rc" -eq 0 ]; then
      return 0
    fi

    warn "Clone failed (likely missing deploy key access)."
    echo ""
    echo "Next step:"
    echo "  1) Copy the public key shown above"
    echo "  2) GitHub → private repo → Settings → Deploy keys → Add deploy key"
    echo "  3) Enable read access (recommended: read-only)"
    echo "  4) Then press ENTER to retry"
    echo ""
    read -r -p "Press ENTER to retry (or Ctrl+C to quit): " _
  done
}

# --- SaaS #1 deploy (saastest)
deploy_app1() {
  local target_dir="$1"
  local domain="$2"

  cd "$target_dir"

  # 1) Ensure .env exists
  if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
      cp .env.example .env
      info "Created .env from .env.example"
    else
      warn "No .env or .env.example found. Continuing."
    fi
  else
    info ".env already exists."
  fi

  # 2) Collect basic auth
  echo ""
  read -r -p "Basic Auth username [admin]: " BASIC_AUTH_USER
  BASIC_AUTH_USER="${BASIC_AUTH_USER:-admin}"

  echo ""
  echo "Enter Basic Auth password (plaintext)."
  echo "It will be hashed locally and only the hash is stored."
  read -r -s -p "Basic Auth password: " BASIC_AUTH_PASS
  echo ""
  [ -n "${BASIC_AUTH_PASS}" ] || die "Password is required."

  # 3) Generate hash (requires docker)
  local DC
  DC="$(docker_cmd)"

  info "Generating BASIC_AUTH_HASH via Caddy..."
  BASIC_AUTH_HASH="$($DC run --rm caddy:2-alpine caddy hash-password --plaintext "$BASIC_AUTH_PASS")"

  # 4) Write caddy.env (IMPORTANT: avoid Compose interpolation issues with $ in bcrypt hashes)
  cat > caddy.env <<EOF
APP_DOMAIN=${domain}
BASIC_AUTH_USER=${BASIC_AUTH_USER}
BASIC_AUTH_HASH=${BASIC_AUTH_HASH}
EOF
  chmod 600 caddy.env || true
  info "Wrote ./caddy.env"

  # 5) Patch docker-compose.yml if it still interpolates BASIC_AUTH_HASH
  if [ -f "docker-compose.yml" ]; then
    if grep -q 'BASIC_AUTH_HASH: \${BASIC_AUTH_HASH' docker-compose.yml 2>/dev/null; then
      info "Patching docker-compose.yml to use env_file ./caddy.env (prevents $ interpolation warnings)..."
      python3 - <<'PY'
import re, pathlib
p = pathlib.Path("docker-compose.yml")
s = p.read_text(encoding="utf-8")

# Replace caddy environment mapping with env_file + environment list
# Works for the known saastest compose layout.
pattern = re.compile(
    r"(^\s*caddy:\s*\n(?:^\s{4}.*\n)*)",
    re.M
)

m = pattern.search(s)
if not m:
    raise SystemExit("Could not locate 'caddy:' service block in docker-compose.yml")

block = m.group(1)

# Remove any existing environment: mapping under caddy
block2 = re.sub(r"^\s{4}environment:\s*\n(?:^\s{6,}.*\n)+", "", block, flags=re.M)

# Insert env_file + environment list after build/context/dockerfile (or after caddy: line)
insert_after = None
lines = block2.splitlines(True)

# Find best insertion point: after dockerfile line if present; otherwise after build block; otherwise after 'caddy:' line
for i, line in enumerate(lines):
    if re.match(r"^\s{6}dockerfile:\s", line):
        insert_after = i
        break
if insert_after is None:
    for i, line in enumerate(lines):
        if re.match(r"^\s{4}build:\s*$", line):
            # insert after the build block (until indentation returns to 4 spaces)
            j = i + 1
            while j < len(lines) and (lines[j].startswith("      ") or lines[j].startswith("        ")):
                j += 1
            insert_after = j - 1
            break
if insert_after is None:
    insert_after = 0

env_snip = "    env_file:\n      - ./caddy.env\n    environment:\n      - APP_DOMAIN\n      - BASIC_AUTH_USER\n      - BASIC_AUTH_HASH\n"
# Insert after insertion point line
if insert_after == 0:
    # after "caddy:" line (which is first line)
    # find first line index that is 'caddy:'
    for i, line in enumerate(lines):
        if re.match(r"^\s*caddy:\s*$", line):
            insert_after = i
            break

lines.insert(insert_after + 1, env_snip)

block3 = "".join(lines)

s2 = s[:m.start(1)] + block3 + s[m.end(1):]
p.write_text(s2, encoding="utf-8")
PY
      info "docker-compose.yml patched."
    else
      # If already using env_file, ensure it's present
      if grep -q 'env_file:' docker-compose.yml; then
        info "docker-compose.yml already uses env_file (good)."
      else
        warn "docker-compose.yml doesn't match expected pattern; no patch applied."
      fi
    fi
  else
    die "docker-compose.yml not found in repo."
  fi

  # 6) Bring up stack
  info "Starting stack (docker compose up -d --build)..."
  $DC compose up -d --build

  echo ""
  info "Deployment finished."
  echo "URL: https://${domain}"
  echo ""
  echo "Useful commands:"
  echo "  cd \"$target_dir\""
  echo "  $DC compose ps"
  echo "  $DC compose logs --tail=200"
}

main() {
  print_header

  menu_select_app
  prompt_inputs_common
  ensure_prereqs
  install_docker_if_missing

  # --- per-app configuration
  REPO_SSH_DEFAULT="$APP1_REPO_DEFAULT"
  echo ""
  read -r -p "Private repo SSH URL [${REPO_SSH_DEFAULT}]: " REPO_SSH
  REPO_SSH="${REPO_SSH:-$REPO_SSH_DEFAULT}"

  # Derive install dir from repo name
  REPO_NAME="$(basename "$REPO_SSH")"
  REPO_NAME="${REPO_NAME%.git}"
  TARGET_DIR="${BASE_DIR}/${REPO_NAME}"

  # Per-app SSH key
  KEY_PATH="$HOME/.ssh/saas_installer_${REPO_NAME}_ed25519"

  ensure_ssh_key "$KEY_PATH"
  retry_clone_until_ok "$REPO_SSH" "$KEY_PATH" "$TARGET_DIR" "$BRANCH"

  case "$APP_ID" in
    1) deploy_app1 "$TARGET_DIR" "$APP_DOMAIN" ;;
  esac
}

main "$@"
