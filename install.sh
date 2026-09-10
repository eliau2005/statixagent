#!/usr/bin/env bash
# StatixAgent one-line installer (MVP §4):
#   curl -fsSL https://raw.githubusercontent.com/eliau2005/statixagent/main/install.sh | sudo bash
# Downloads the latest release for this architecture and launches the TUI wizard.
set -euo pipefail

REPO="eliau2005/statixagent"
TMP="$(mktemp -d /tmp/statix-install.XXXXXX)"
trap 'rm -rf "$TMP"' EXIT

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (sudo) — the installer writes /usr/local/bin and /etc." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

# Optional, never installed here: /firewall drives ufw. Without it the agent
# reports the firewall as unmanaged instead of guessing at another backend.
command -v ufw >/dev/null 2>&1 || \
  echo "Note: ufw not found — /firewall will report the firewall as unmanaged."

echo "Fetching latest release info..."
LATEST_JSON="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest")"
url_for() {
  echo "$LATEST_JSON" | grep -o "\"browser_download_url\"[^\"]*\"[^\"]*$1\"" | grep -o 'https://[^"]*' | head -1
}

AGENT_URL="$(url_for "statix-agent_linux_${ARCH}")"
INSTALL_URL="$(url_for "statix-install_linux_${ARCH}")"
SUMS_URL="$(url_for "checksums.txt")"
if [ -z "$AGENT_URL" ] || [ -z "$INSTALL_URL" ]; then
  echo "Could not find release assets for linux/${ARCH}." >&2
  exit 1
fi

echo "Downloading agent and installer..."
curl -fsSL -o "$TMP/statix-agent" "$AGENT_URL"
curl -fsSL -o "$TMP/statix-install" "$INSTALL_URL"

if [ -n "$SUMS_URL" ]; then
  curl -fsSL -o "$TMP/checksums.txt" "$SUMS_URL"
  (cd "$TMP" && grep -E "statix-(agent|install)_linux_${ARCH}\$" checksums.txt \
    | sed -E "s/  statix-agent_linux_${ARCH}\$/  statix-agent/; s/  statix-install_linux_${ARCH}\$/  statix-install/" \
    | sha256sum -c -)
fi

chmod +x "$TMP/statix-agent" "$TMP/statix-install"
echo "Launching the configuration wizard..."
exec "$TMP/statix-install" --agent-binary "$TMP/statix-agent"
