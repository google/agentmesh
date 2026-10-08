#!/usr/bin/env bash
set -euo pipefail

REPO="google/sam"
INSTALL_DIR="/usr/local/bin"

echo "Installing SAM from $REPO..."

# Get OS and Arch
OS="$(uname -s)"
case "${OS}" in
    Linux*)     OS_NAME="Linux";;
    Darwin*)    OS_NAME="Darwin";;
    *)          echo "Unsupported OS: ${OS}"; exit 1;;
esac

ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64*)    ARCH_NAME="x86_64";;
    aarch64*)   ARCH_NAME="arm64";;
    arm64*)     ARCH_NAME="arm64";;
    *)          echo "Unsupported architecture: ${ARCH}"; exit 1;;
esac

# Get latest release version via GitHub redirect (avoids api.github.com rate limits)
echo "Fetching latest release information..."
VERSION=$(curl -fsSL -o /dev/null -w "%{url_effective}" "https://github.com/${REPO}/releases/latest" | sed 's|.*/||' || true)
if [ -z "$VERSION" ] || [ "$VERSION" = "releases" ]; then
    # Only a mesh release (tag v*) carries the binaries; SDK and mobile releases
    # (sdk/js/v*, sdk/python/v*, mobile/v*) share the list.
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases?per_page=100" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | grep -E '^v[0-9]' | head -n 1 || true)
fi

if [ -z "$VERSION" ] || [ "$VERSION" = "releases" ]; then
    echo "Error: Could not find the latest release."
    exit 1
fi

echo "Found latest version: ${VERSION}"

# Construct download URL (matches goreleaser name template)
TAR_NAME="sam_${OS_NAME}_${ARCH_NAME}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${TAR_NAME}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

# Create a temporary directory
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
cd "$TMP_DIR"

echo "Downloading ${DOWNLOAD_URL}..."
if ! curl -sfL -o "${TAR_NAME}" "${DOWNLOAD_URL}"; then
    echo "Error: Failed to download ${DOWNLOAD_URL}"
    exit 1
fi

echo "Downloading ${CHECKSUMS_URL}..."
if ! curl -sfL -o checksums.txt "${CHECKSUMS_URL}"; then
    echo "Error: Failed to download ${CHECKSUMS_URL}"
    exit 1
fi

echo "Verifying SHA-256 checksum..."
EXPECTED_SUM=$(awk -v f="${TAR_NAME}" '$2 == f {print $1}' checksums.txt)
if [ -z "${EXPECTED_SUM}" ]; then
    echo "Error: ${TAR_NAME} not found in checksums.txt"
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SUM=$(sha256sum "${TAR_NAME}" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SUM=$(shasum -a 256 "${TAR_NAME}" | awk '{print $1}')
else
    echo "Error: Neither sha256sum nor shasum is available to verify archive integrity."
    exit 1
fi
if [ "${EXPECTED_SUM}" != "${ACTUAL_SUM}" ]; then
    echo "Error: SHA-256 checksum mismatch for ${TAR_NAME} (expected ${EXPECTED_SUM}, got ${ACTUAL_SUM})"
    exit 1
fi

echo "Extracting..."
tar -xzf "${TAR_NAME}"

echo "Installing to ${INSTALL_DIR} (may require sudo)..."
INSTALLED_BINS=()
for b in sam-one sam-node sam-control-plane sam-router mcp-client sam-console; do
    if [ -f "$b" ]; then
        INSTALLED_BINS+=("$b")
    fi
done

if [ ${#INSTALLED_BINS[@]} -eq 0 ]; then
    echo "Error: No SAM binaries found in release archive."
    exit 1
fi

if [ -w "$INSTALL_DIR" ]; then
    mv "${INSTALLED_BINS[@]}" "$INSTALL_DIR/"
else
    sudo mv "${INSTALLED_BINS[@]}" "$INSTALL_DIR/"
fi

# Cleanup
cd - > /dev/null
rm -rf "$TMP_DIR"

echo "Successfully installed SAM (${VERSION}) to ${INSTALL_DIR}"
echo "Run 'sam-node --help' to get started."
