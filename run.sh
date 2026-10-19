#!/usr/bin/env bash
# ==============================================================================
# KubeScope - Universal Launcher for macOS and Linux
# ==============================================================================

set -e

PORT=8930
URL="http://localhost:${PORT}/"

# Resolve script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

echo "======================================================="
echo "  [*] KubeScope - Kubernetes 異常透視與白話排障軍師"
echo "  平台支援: macOS / Linux / Windows"
echo "======================================================="

# 1. Check Python 3
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "[!] 錯誤：未偵測到 Python 3 環境！請先安裝 Python 3.10 或更新版本。"
    exit 1
fi

echo "[1/2] 檢測到 Python 環境: $(${PYTHON_CMD} --version)"

# 2. Check Ollama
if curl -s --max-time 1 "http://localhost:11434/api/tags" >/dev/null 2>&1; then
    echo "[2/2] [OK] 地端 Ollama AI 服務正在運行中"
else
    echo "[2/2] [INFO] 地端 Ollama 未啟動，系統將自動切換為「內建離線 SRE 專家庫」"
fi

echo "======================================================="
echo "  Web 控制台: ${URL}"
echo "  正在啟動服務並自動開啟瀏覽器..."
echo "======================================================="

# Open browser in background
open_browser() {
    sleep 1
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        open "${URL}" >/dev/null 2>&1 || true
    elif command -v xdg-open >/dev/null 2>&1; then
        # Linux with Desktop GUI
        xdg-open "${URL}" >/dev/null 2>&1 || true
    elif command -v sensible-browser >/dev/null 2>&1; then
        sensible-browser "${URL}" >/dev/null 2>&1 || true
    fi
}
open_browser &

# Start KubeScope Server
exec ${PYTHON_CMD} "${SCRIPT_DIR}/server.py"
