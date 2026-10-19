# KubeScope Launcher & Environment Doctor
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "KubeScope - Kubernetes Diagnostics and SRE Copilot"

Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "    KubeScope - Kubernetes 異常透視與白話排障軍師" -ForegroundColor Cyan
Write-Host "    Zero-Agent Cluster Triage, CVE Scanner and Upgrade Advisor" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. 檢測 Python 執行環境
$pythonCmd = $null

if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = "py -3"
} else {
    $localPy = Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($localPy) {
        $pythonCmd = $localPy.FullName
    }
}

if (-not $pythonCmd) {
    Write-Host "[!] 錯誤：未偵測到 Python 執行環境！" -ForegroundColor Red
    Write-Host "KubeScope 需要 Python 3.10+ 環境。" -ForegroundColor Yellow
    Read-Host "按 Enter 鍵關閉視窗..."
    exit 1
}

Write-Host "[1/3] 檢測到 Python 環境：" -ForegroundColor Green -NoNewline
Write-Host " $pythonCmd" -ForegroundColor White
$ver = & $pythonCmd --version 2>&1
Write-Host "      版本：$ver" -ForegroundColor Gray
Write-Host ""

# 2. 檢測 kubectl 工具狀態
Write-Host "[2/3] 檢查本地 kubectl 工具狀態..." -ForegroundColor Yellow
if (Get-Command kubectl -ErrorAction SilentlyContinue) {
    Write-Host "      [OK] 本機已配置 kubectl 指令工具" -ForegroundColor Green
} else {
    Write-Host "      [INFO] 本機未安裝 kubectl (KubeScope 支援離線純文字/JSON貼上與遠端日誌分析)" -ForegroundColor Gray
}
Write-Host ""

# 3. 檢查 Ollama 地端 AI 狀態
Write-Host "[3/3] 檢查地端 Ollama AI 服務..." -ForegroundColor Yellow
try {
    $ollamaCheck = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 1 -ErrorAction Stop
    $modelCount = $ollamaCheck.models.Count
    Write-Host "      [OK] Ollama 正在運行中，偵測到 $modelCount 個本地模型" -ForegroundColor Green
} catch {
    Write-Host "      [INFO] Ollama 服務未開啟，系統將自動啟用「內建離線 SRE 專家決策樹」" -ForegroundColor Gray
}
Write-Host ""

# 4. 啟動 Web 服務並自動開啟瀏覽器
$targetUrl = "http://localhost:8930/"
Write-Host "===================================================================" -ForegroundColor Green
Write-Host " 正在啟動 KubeScope 本機伺服器 (Port: 8930)..." -ForegroundColor Green
Write-Host " 控制台網址: $targetUrl" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Green
Write-Host ""

Start-Process $targetUrl
& $pythonCmd "$PSScriptRoot\server.py"