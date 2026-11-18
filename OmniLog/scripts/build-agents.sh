#!/usr/bin/env bash
# ==============================================================================
# Force-Fields Agent Cross-Compilation Script
# Produces standalone, zero-dependency binaries for Windows and Linux amd64.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
AGENT_DIR="${ROOT_DIR}/agent"
BIN_DIR="${ROOT_DIR}/bin"

mkdir -p "$BIN_DIR"

echo "=========================================================="
echo "   COMPILING FORCE-FIELDS AGENT (WINDOWS & LINUX AMD64)   "
echo "=========================================================="

cd "$AGENT_DIR"

# 1. Compile for Windows x64
echo "[+] Building Windows x64 binary..."
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "${BIN_DIR}/forcefields-agent-windows-amd64.exe" ./cmd/agent
echo "[✓] Windows binary: ${BIN_DIR}/forcefields-agent-windows-amd64.exe"

# 2. Compile for Linux x64
echo "[+] Building Linux x64 binary..."
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o "${BIN_DIR}/forcefields-agent-linux-amd64" ./cmd/agent
echo "[✓] Linux binary: ${BIN_DIR}/forcefields-agent-linux-amd64"

echo "=========================================================="
echo "Binaries generated in ${BIN_DIR}:"
ls -lh "$BIN_DIR"

if command -v sha256sum &> /dev/null; then
    echo ""
    echo "SHA-256 Checksums:"
    sha256sum "${BIN_DIR}"/*
fi
echo "=========================================================="
