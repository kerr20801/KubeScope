# KubeScope Launcher & Environment Doctor
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = 'KubeScope - Kubernetes 異常透視與白話排障軍師'

Write-Host '===================================================================' -ForegroundColor Cyan
Write-Host '    [KubeScope] Kubernetes 異常透視與白話排障軍師' -ForegroundColor Cyan
Write-Host '    Zero-Agent Cluster Triage, CVE Scanner and Upgrade Advisor' -ForegroundColor Cyan
Write-Host '===================================================================' -ForegroundColor Cyan
Write-Host ''

# 1. 檢測 Python 執行環境
$pythonCmd = $null

if (Get-Command python -ErrorAction SilentlyContinue) {
    $pythonCmd = 'python'
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $pythonCmd = 'py -3'
} else {
    $localPy = Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($localPy) {
        $pythonCmd = $localPy.FullName
    }
}

if (-not $pythonCmd) {
    Write-Host '[!] 提示：電腦尚未安裝 Python 執行環境！' -ForegroundColor Yellow
    Write-Host '    KubeScope 需要 Python 3.10+ 環境。' -ForegroundColor Gray
    Write-Host ''
    Write-Host '    [1] 自動透過 Windows 官方套件庫 winget 一鍵安裝 Python 3.11' -ForegroundColor Cyan
    Write-Host '    [2] 前往官網手動下載' -ForegroundColor Gray
    Write-Host ''
    $choice = Read-Host '請輸入選項 預設 1'
    if ($choice -eq '' -or $choice -eq '1') {
        Write-Host '[*] 正在透過 winget 自動下載並靜默安裝 Python 3.11，請稍候約 1~2 分鐘...' -ForegroundColor Green
        try {
            & winget install --id Python.Python.3.11 -e --silent --accept-package-agreements --accept-source-agreements
            Write-Host '[OK] Python 安裝完成！請重新雙擊「啟動服務.bat」即可！' -ForegroundColor Green
            Read-Host '按 Enter 鍵關閉...'
            exit 0
        } catch {
            Write-Host '[!] 自動安裝遭遇錯誤，請手動前往 https://www.python.org/downloads/ 安裝。' -ForegroundColor Red
        }
    } else {
        Start-Process 'https://www.python.org/downloads/'
        exit 0
    }
}

Write-Host '[1/3] 檢測到 Python 環境：' -ForegroundColor Green -NoNewline
Write-Host " $pythonCmd" -ForegroundColor White
$ver = & $pythonCmd --version 2>&1
Write-Host "      版本：$ver" -ForegroundColor Gray
Write-Host ''

# 2. 檢測 kubectl 工具狀態
Write-Host '[2/3] 檢查本地 kubectl 工具狀態...' -ForegroundColor Yellow
if (Get-Command kubectl -ErrorAction SilentlyContinue) {
    Write-Host '      [OK] 本機已配置 kubectl 指令工具' -ForegroundColor Green
} else {
    Write-Host '      [INFO] 本機未安裝 kubectl (KubeScope 支援離線純文字/JSON貼上與遠端日誌分析)' -ForegroundColor Gray
}
Write-Host ''

# 3. 檢查 Ollama 地端 AI 狀態
Write-Host '[3/3] 檢查地端 Ollama AI 服務...' -ForegroundColor Yellow
try {
    $ollamaCheck = Invoke-RestMethod -Uri 'http://localhost:11434/api/tags' -TimeoutSec 1 -ErrorAction Stop
    $modelCount = $ollamaCheck.models.Count
    Write-Host "      [OK] Ollama 正在運行中，偵測到 $modelCount 個本地模型" -ForegroundColor Green
} catch {
    Write-Host '      [INFO] Ollama 服務未開啟或尚未安裝。' -ForegroundColor Gray
    Write-Host '             先吃定心丸：KubeScope 內建純 Python 離線 SRE 專家決策庫，免裝 AI 也能 100% 正常排障！' -ForegroundColor Cyan
    Write-Host '             文書筆電若想開啟對話，建議安裝 Ollama 後執行輕量模型：' -ForegroundColor Gray
    Write-Host '             ollama run qwen2.5:1.5b  (不到 1GB，純 CPU 秒回)' -ForegroundColor DarkGray
    Write-Host '             ollama run qwen3.5:2b   (輕量首選)' -ForegroundColor DarkGray
}
Write-Host ''

# 4. 啟動 Web 服務並自動開啟瀏覽器
$targetUrl = 'http://localhost:8930/'
Write-Host '===================================================================' -ForegroundColor Green
Write-Host ' 正在啟動 KubeScope 本機伺服器 (Port: 8930)...' -ForegroundColor Green
Write-Host " 控制台網址: $targetUrl" -ForegroundColor Cyan
Write-Host '===================================================================' -ForegroundColor Green
Write-Host ''

Start-Process $targetUrl
& $pythonCmd "$PSScriptRoot\server.py"
