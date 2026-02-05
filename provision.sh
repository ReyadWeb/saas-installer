#!/usr/bin/env bash
set -euo pipefail

# public/provision.sh
# Public bootstrapper for "deploy-any-app-like-this"
#
# Goal:
# - A user can run:
#     bash <(curl -fsSL https://your-public-host/provision.sh)
# - The script installs prerequisites, clones a *private* GitHub repo via SSH (if the user has a key),
#   then runs the repo's setup + deploy scripts.
#
# SECURITY MODEL:
# - The script is public.
# - The *repo stays private*. Only users with an SSH key that has access (Deploy Key or GitHub user key)
#   can clone/install.
#
# This script is interactive by design.

die() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || die "sudo not found (install sudo or run as root)."
  SUDO="sudo"
fi

# --- Inputs
echo ""
echo "=== App Provisioning (SSH private repo) ==="
read -r -p "GitHub SSH repo (e.g. git@github.com:ReyadWeb/saastest.git): " REPO_SSH
[ -n "${REPO_SSH}" ] || die "Repo SSH URL is required."

read -r -p "Branch (blank = default): " BRANCH

DEFAULT_BASE="$HOME/apps"
read -r -p "Install directory base [${DEFAULT_BASE}]: " BASE_DIR
BASE_DIR="${BASE_DIR:-$DEFAULT_BASE}"

REPO_NAME="$(basename "${REPO_SSH}")"
REPO_NAME="${REPO_NAME%.git}"
TARGET_DIR="${BASE_DIR}/${REPO_NAME}"

echo ""
read -r -p "Domain for app (e.g. portal.example.com): " APP_DOMAIN
[ -n "${APP_DOMAIN}" ] || die "Domain is required."

# --- Prereqs
info "Installing prerequisites (git, curl, ca-certificates)..."
$SUDO apt-get update -y
$SUDO apt-get install -y git curl ca-certificates

# --- SSH key check
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"

DEFAULT_KEY="$HOME/.ssh/id_ed25519"
read -r -p "SSH private key path [${DEFAULT_KEY}]: " SSH_KEY
SSH_KEY="${SSH_KEY:-$DEFAULT_KEY}"

if [ ! -f "$SSH_KEY" ]; then
  echo ""
  echo "No SSH key found at: $SSH_KEY"
  read -r -p "Generate a new key now? (y/N): " GEN
  GEN="${GEN:-N}"
  if [[ "$GEN" =~ ^[Yy]$ ]]; then
    ssh-keygen -t ed25519 -C "app-provision" -f "$SSH_KEY"
    chmod 600 "$SSH_KEY"
    echo ""
    echo "Public key (add this to GitHub as a Deploy Key on the repo):"
    echo "---------------------------------------------------------"
    cat "${SSH_KEY}.pub"
    echo "---------------------------------------------------------"
    echo ""
    read -r -p "Press Enter after adding the deploy key in GitHub..."
  else
    die "SSH key is required to clone private repo."
  fi
fi

# Ensure SSH config uses provided key for github.com
SSH_CONFIG="$HOME/.ssh/config"
touch "$SSH_CONFIG"
chmod 600 "$SSH_CONFIG"

if ! grep -q "Host github.com" "$SSH_CONFIG" 2>/dev/null; then
  cat >> "$SSH_CONFIG" <<EOF

Host github.com
  HostName github.com
  User git
  IdentityFile ${SSH_KEY}
  IdentitiesOnly yes
EOF
else
  info "~/.ssh/config already has a github.com host entry; leaving it as-is."
fi

# --- Clone/update repo
info "Preparing directory: ${TARGET_DIR}"
mkdir -p "$BASE_DIR"

if [ -d "$TARGET_DIR/.git" ]; then
  info "Repo exists; pulling latest..."
  if [ -n "${BRANCH}" ]; then
    git -C "$TARGET_DIR" fetch --all --prune
    git -C "$TARGET_DIR" checkout "$BRANCH"
    git -C "$TARGET_DIR" pull --ff-only origin "$BRANCH"
  else
    git -C "$TARGET_DIR" pull --ff-only
  fi
else
  info "Cloning repo..."
  if [ -n "${BRANCH}" ]; then
    git clone --branch "$BRANCH" "$REPO_SSH" "$TARGET_DIR"
  else
    git clone "$REPO_SSH" "$TARGET_DIR"
  fi
fi

# --- Validate scripts exist
[ -f "$TARGET_DIR/scripts/ubuntu-setup.sh" ] || die "Missing scripts/ubuntu-setup.sh in repo."
[ -f "$TARGET_DIR/scripts/deploy.sh" ]       || die "Missing scripts/deploy.sh in repo."

chmod +x "$TARGET_DIR/scripts/ubuntu-setup.sh" "$TARGET_DIR/scripts/deploy.sh" || true

# --- Run setup + deploy
info "Running Ubuntu setup (Docker install)..."
bash "$TARGET_DIR/scripts/ubuntu-setup.sh"

info "Running deploy (creates env + starts stack)..."
cd "$TARGET_DIR"
# Pre-seed domain so deploy.sh uses it as default (still asks for password)
if [ ! -f "caddy.env" ]; then
  cat > caddy.env <<EOF
APP_DOMAIN=${APP_DOMAIN}
BASIC_AUTH_USER=admin
BASIC_AUTH_HASH=
EOF
  chmod 600 caddy.env
else
  # overwrite APP_DOMAIN only
  sed -i "s/^APP_DOMAIN=.*/APP_DOMAIN=${APP_DOMAIN}/" caddy.env || true
fi

bash "$TARGET_DIR/scripts/deploy.sh"

info "All done."
echo "Open: https://${APP_DOMAIN}"
