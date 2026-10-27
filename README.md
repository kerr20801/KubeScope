# ⬡ KubeScope — Kubernetes 異常透視與白話排障軍師

<div align="center">

[![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-blue.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Zero-Agent](https://img.shields.io/badge/Zero--Agent-100%25%20In--Cluster%20Free-emerald.svg)]()
[![Zero-Dependency](https://img.shields.io/badge/Dependencies-0%20External%20Pip%20Packages-orange.svg)]()
[![Air-Gapped](https://img.shields.io/badge/Privacy-100%25%20Air--Gapped%20Local-success.svg)]()
[![Supply Chain](https://img.shields.io/badge/Integrity-SHA256%20Anti--Tamper-success.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**專為網路工程師、系統管理員 (SysAdmin)、初入 K8s 的開發者與機房維運人員打造的輕量零侵入 Kubernetes 異常透視、CVE 漏洞快篩與升級導引軍師！**  
**100% 純唯讀 ｜ 零叢集 Agent ｜ 斷網氣隙機房可用 ｜ 白話病因切片 ｜ 拒絕黑盒子自走砲（Copilot, not Autopilot）**

</div>

---

## 🌟 解決什麼核心痛點？

在維護 Kubernetes 叢集時，非專職 K8s SRE 的工程師經常面臨四大崩潰折磨：

1. **資訊海嘯，只報紅燈卻不說「人話」**：
   * 像 Lens 或 k9s 只是將 YAML 與狀態平鋪在畫面上。看到紅色的 `CrashLoopBackOff`、`OOMKilled` 或 `Pending`，多數人根本不知道背後到底發生了什麼事，更不知道「下一步該下哪條指令」。
2. **生產機房嚴禁在叢集內裝東裝西**：
   * 大多數商業監控工具非得在叢集裡用 Helm 裝一大堆 DaemonSet、Operator 與特權 CRD。在客戶機房或企業嚴格環境下，**資安絕對不放行，也拿不到 cluster-admin 授權**。
3. **沒有人敢讓 AI 自動亂改生產環境**：
   * 某些自走砲 AI Agent 標榜「自動修復 K8s」，但在正式營運環境，**沒有任何維運人員敢讓 AI 自主執行 `kubectl delete/patch`**！
   * 現場真正需要的是：**「白話剖析病因 ➔ 提取精準關鍵日誌 ➔ 產出安全可驗證的指令由工程師複製執行」的 SRE 隨身軍師**！
4. **升版恐懼症與資安 CVE 盲區**：
   * 很多人不知道 K8s 官方僅支援 N ➔ N+1 升級，跨版直升會導致叢集毀滅性癱瘓。
   * 不清楚自己的 K8s 版本是否暴露在重大 CVE (如 Kubelet 越權掛載、指令注入)，也不知道有哪些舊版 API (如 PSP、v1beta1 Ingress) 在新版已被強制刪除。

---

## 🚀 八大核心功能模組矩陣

### 模組 1：🧭 實戰排障操作流四部曲 (Interactive Troubleshooting Workbench)
手把手引導你完成標準 SRE 排查流程：
* **第 1 動：檢查節點健康度 (`kubectl get nodes -o wide`)**：解析節點 Ready 狀態、OS 系統與 Kubelet 版本。
* **第 2 動：篩查命名空間 Pods (`kubectl get pods -A -o wide`)**：貼上終端機文字表格，自動標示 🟢 正常、🔴 CrashLoopBackOff / Error、🟡 Pending、`Init:0/1` 卡死與 `Evicted` 殘留。
  * 🏷️ **Namespace 智慧過濾**：支援下拉選單即時依命名空間篩選 Pods，並提供 **`➕ 建立新 Namespace`** 快捷入口。
  * 點選異常 Pod 即刻鎖定目標並自動產生精準排查指令！
* **第 3 動：智能組裝取證神鑰匙**：
  * 🔑 **撈取死亡遺言 (90% 人都不知道)**：`kubectl logs -n <ns> <pod> --previous --tail=200`
  * 🔑 **InitContainer 卡死撈取**：`kubectl logs -n <ns> <pod> -c <init-container>`
  * 📜 **即時日誌**：`kubectl logs -n <ns> <pod> --tail=200`
  * 🔍 **Kubelet 調度與探針事件**：`kubectl describe pod -n <ns> <pod>`
* **第 4 動：日誌深度法醫與白話翻譯 (Log Forensic Analyzer)**：過濾幾萬行 INFO 心跳，只提取致命 Panic、OOM 137、DB 連線拒絕、缺少設定檔，並直接附上可複製的驗證與修復指令！

### 模組 2：🌐 全鏈路路由拓撲透視 (Traffic Route Tracer)
透視五層流量拓撲鏈：`Client 請求 ➔ Ingress (域名/路徑) ➔ Service (端口/選擇器) ➔ Endpoints (就緒實體) ➔ Pods (容器埠號/探針)`。
* ❌ **Ingress 懸空**：Ingress 指向不存在的 Service (404/503)。
* ❌ **標籤選擇器懸空**：Service selector 與 Pod labels 不吻合，Endpoints 為空導致 503 服務黑洞。
* ❌ **探針失敗踢除**：Pod 存在但 Readiness 就緒探針未通過，遭 Endpoints 全數下線。

### 模組 3：🔐 控制面憑證、KubeAPI 探針與 IPAM 健檢 (Infra Doctor)
* **Kubeadm PKI 憑證壽命審計 (`kubeadm certs check-expiration`)**：查驗 `admin.conf`、`apiserver` 等憑證，警示 30 天內臨期憑證並提供一鍵更新指令 (`kubeadm certs renew all`)。
* **憑證過期災難還原手冊 (Emergency Cert Recovery Playbook)**：針對憑證已完全過期、`kubectl` 斷線拒絕連線 (`x509: certificate has expired`) 的絕境，提供純本機端 7 步驟搶救指南（備份 PKI、重新簽署、產出 kubeconfig、靜態 Pod 重啟）。
* **Kube-APIServer `/readyz` 深度狀態剖析**：深度檢驗 etcd 寫入延遲逾時 (>100ms) 與 Webhook 卡死阻塞。
* **IPAM 子網耗盡與 CoreDNS 常備排障清單**：預防 `no IP addresses available in range` 與 `ndots:5` 延遲陷阱。

### 模組 4：🩺 ETCD 深度體檢與 Kubelet 故障排除 (ETCD & Kubelet Diagnostics)
* **ETCD 深度體檢與維護命令組裝**：
  * 解析端點健康狀態、Leader 角色變更與 Commit 寫入延遲 (>100ms 磁碟 I/O 警示)。
  * 監控 DB 儲存空間 (DB Size) 與 `NOSPACE` 配額耗盡報警。
  * 自動生成四大維護安全指令：**etcdctl 快照備份**、**資料壓縮 (compact)**、**碎片重整 (defrag)** 與 **解除警報 (alarm disarm)**。
* **Kubelet 系統服務深度除錯**：
  * 剖析 `journalctl -u kubelet` 或 `systemctl status kubelet` 日誌。
  * 精準捕捉 **Swap 開啟致命拒絕** (`Running with swap on is not supported`)。
  * 診斷 **Cgroup Driver 不相容** (`systemd` vs `cgroupfs`)。
  * 識別 **NodePressure 節點資源耗盡驅逐** (DiskPressure / MemoryPressure Evictions)。

### 模組 5：🛠️ YAML 修復室與安全 Namespace 建立 (YAML Studio & Namespace Manager)
* **安全 Namespace 規範生成器**：
  * 一鍵產出符合 Kubernetes 官方 **Pod Security Standards (PSS)** 規範的命名空間 YAML（`baseline` 或 `restricted`）。
  * 自動附帶 **ResourceQuota**（防記憶體與 CPU 資源掠奪）與 **LimitRange**（預設與上限防護）。
* **OOMKilled 資源補丁 (`Resource Limit Bump Patch`)**：
  * 一鍵產出拉高 Memory/CPU Limits 的 Patch YAML 與 `kubectl patch deployment` 即用指令。
* **Service 標籤懸空修復 (`Selector Fix`)**：
  * 快速比對 Pod 實際標籤，一鍵校正 Service 選擇器，立即解除 503 服務黑洞。
* **探針初始延遲修復 (`Probe Fix`)**：
  * 針對啟動慢但探針太快打死的容器，自動生成合理 `initialDelaySeconds` 與 `failureThreshold` 補丁。

### 模組 6：🛡️ K8s 版本與組件 CVE 漏洞掃描儀 (CVE Security Scanner)
* **內建 Air-Gapped 離線高危 CVE 資料庫**：涵蓋 CVE-2024-3177、CVE-2023-3676 (Windows Kubelet 提權)、CVE-2023-5528、CVE-2018-1002105 (神級遠端代碼執行) 等。
* **智慧版本比對**：輸入版本即刻輸出受影響漏洞清單、CVSS 風險評分與官方建議修補版本。

### 模組 7：🗺️ 升版教學與平滑導航儀 (Upgrade Advisor & Playbook)
* **跨版本跳級防呆 (Version Hopping Guard)**：自動推算多階段升級路徑（例如：`v1.24.2 ➔ v1.25.16 ➔ v1.26.15 ➔ v1.27.0`），禁止跨版直升！
* **已廢棄 API 移除預警 (API Deprecation Audit)**：偵測目標版本移除的廢棄 API（如 v1.25 移除 PSP），提供 YAML 遷移對照。
* **逐步操作手冊 (Step-by-Step Runbook)**：完整包含 etcd 災難還原快照與平滑升級指令包。

### 模組 8：🤖 本地 SRE 隨身軍師 (AI Copilot with Local Ollama)
* **分析完畢主動戰報（Proactive Briefing）**：一鍵分析後 Copilot 第一時間主動發布 SRE 戰情速報，無須手動貼文字！
* **卡片一鍵呼叫 AI 深入推演**：點擊異常 Pod 或 Service 卡片直接帶入上下文開始推演。
* **連續多輪上下文記憶 (Multi-Turn Continuous Memory)**：保留全機遙測快照 + 最近 4 輪 Q&A 一問一答，連續追問絕不失憶！
* **三大實戰鐵律**：強制繁體中文、切中要害零教科書廢話、直給可以直接貼入終端機的 `kubectl` 指令！
* **文書筆電超輕量模型專屬適配**：文書機首選 `qwen2.5:1.5b`（不到 1GB，純 CPU 秒回）或 `qwen3.5:2b`。

---

## 🔰 小白 / 輕薄文書筆電專用：零門檻 3 步驟懶人上手指南

> [!TIP]
> **先吃一顆定心丸**：**你完全不需要安裝 Ollama，也能 100% 正常使用 KubeScope 進行全功能排障！**  
> 核心的「Pod 崩潰法醫」、「Service 黑洞偵測」、「CVE 漏洞快篩」、「跨版本升級推算」與「自動產生取證 CLI」，全部由內建純 Python 標準庫毫秒級完成，根本不需要 GPU，也不需要 LLM！

---

### 第一步：安裝 Python（如果電腦連 Python 都沒有）
* **直接雙擊 `啟動服務.bat`（推薦）**：
  若偵測到未安裝 Python，視窗會自動提示輸入 `1`，系統將自動透過 Windows 官方 `winget` 一鍵下載並配置好 Python 3.11，全程不需手動下載！
* **手動下載**：前往 [Python 官方網站](https://www.python.org/downloads/) 下載安裝（**請務必勾選「Add python.exe to PATH」**）。

---

### 第二步：啟動 KubeScope（雙擊即用）
* **Windows**：直接雙擊資料夾內的 **`啟動服務.bat`**。
* **macOS / Linux**：執行 `./run.sh` 或 `python3 server.py`。
* 預設瀏覽器會自動開啟控制台：`http://localhost:8930/`。
* **字體大小隨心調**：頂端導航列提供 **`字體大小: [A-] [標準] [A+]`**，高解析度筆電與大螢幕可隨時放大閱讀！

---

### 第三步：（可選）普通文書筆電想開啟「地端 SRE 軍師對話」怎麼做？
如果你手邊是一台**普通筆電（如 8GB 記憶體、無獨立顯示卡、只有 CPU）**，想要跟 AI 即時對話：

1. **安裝 Ollama（只需 1 分鐘）**：前往 [Ollama 官方網站 (ollama.com)](https://ollama.com/download) 下載安裝完成。
2. **普通筆電最佳輕量模型推薦（複製指令執行）**：
   * 🚀 **極致省電 / 8GB 普通筆電首選（不到 1GB，純 CPU 秒回）**：
     ```bash
     ollama run qwen2.5:1.5b
     ```
   * ⚡ **輕量維運平衡版 (2B)**：
     ```bash
     ollama run qwen3.5:2b
     ```
   * 🏆 **旗艦版 (有 8GB+ 獨立顯卡或 16GB+ 記憶體)**：
     ```bash
     ollama run qwen3.5:latest
     ```
3. 重新整理 KubeScope 網頁，右上角狀態燈會自動變成 `🟢 Ollama: 已連線`！
   * *註：若機房現場完全斷網或沒開 Ollama，KubeScope 會自動切換為【🛡️ SRE 離線專家決策庫】，依然能針對所有故障提供精準回答！*

---

## 📁 專案目錄結構

```text
KubeScope/
  ├── core/
  │    ├── parser.py           # K8s 表格、describe 與日誌文字正則剖析器
  │    ├── route_tracer.py     # 全鏈路路由拓撲 (Ingress➔Service➔Endpoints➔Pods) 透視
  │    ├── infra_doctor.py     # 憑證到期審計、ETCD 體檢、Kubelet 故障排除與災難手冊
  │    ├── yaml_workbench.py   # YAML 修復室 (PSS 安全 Namespace、OOM 補丁、選擇器與探針校正)
  │    ├── log_analyzer.py     # 深度日誌法醫、致命錯誤行切片與白話翻譯引擎
  │    ├── diagnostician.py    # Pod 深度法醫(Init/探針/Evicted)、流量黑洞與反模式引擎
  │    ├── cve_scanner.py      # K8s 離線 CVE 漏洞庫與語意版本比對引擎
  │    ├── upgrade_advisor.py  # 升級路徑推算、廢棄 API 預警與逐步 Runbook 生成
  │    ├── supply_chain.py     # 依賴包仿冒 (Typosquatting) 與容器特權越權審計儀
  │    └── llm_gateway.py      # 地端 Ollama 串接、多輪記憶與離線 SRE 專家決策庫
  ├── web/
  │    └── index.html          # 現代化純前端面板 (操作流 + 路由拓撲 + 憑證/ETCD/Kubelet + YAML 修復室 + AI 軍師)
  ├── samples/
  │    ├── sample_cluster_issues.json           # 實戰綜合故障事故範例 (OOM + Crash + 服務黑洞)
  │    ├── sample_healthy_cluster.json          # 正常健康叢集 (100分演示)
  │    ├── sample_cve_legacy.json               # 老舊叢集 (含 CVE 與廢棄 API 樣本)
  │    ├── sample_broken_routes.json            # 路由斷鏈示範包 (選擇器懸空 + 探針失敗)
  │    ├── sample_kubeadm_certs.txt             # kubeadm 憑證到期範例
  │    ├── sample_etcd_status.txt               # ETCD endpoint health 與 status 狀態範例
  │    ├── sample_kubelet_error.txt             # Kubelet Swap 與 Cgroup 報錯範例
  │    ├── sample_readyz.txt                    # /readyz 內部探針失敗範例
  │    └── sample_vulnerable_requirements.txt   # 惡意仿冒套件與浮動版本範例
  ├── server.py                # 零依賴 Python RESTful API 伺服器 (埠號 8930，支援全平台)
  ├── test_engine.py           # 自動化迴歸測試套件 (涵蓋法醫診斷、CVE、升級推算、供應鏈、YAML、ETCD)
  ├── verify_integrity.py      # SHA-256 全文代碼防偽與防竄改驗證儀
  ├── SHA256SUMS.txt           # 官方加密雜湊簽名清單 (防竄改白名單)
  ├── launcher.ps1             # Windows PowerShell 環境檢查與啟動引導 (支援 winget 安裝)
  ├── 啟動服務.bat              # Windows 滑鼠雙擊極速啟動
  ├── run.sh                   # macOS / Linux 一鍵極速啟動腳本
  ├── requirements.txt         # 零強制外部依賴聲明 (天生免疫 PyPI 供應鏈攻擊)
  ├── LICENSE                  # MIT 開源授權協議
  └── README.md                # 專案詳細說明文件
```

---

## 👨‍💻 作者 (Authors)

* **Kerr** ([@kerr20801](https://github.com/kerr20801)) — 專案構思、架構設計與維運實戰場景引導。
* **Google Gemini** (Gemini Code Assist) — AI 結對編程 (AI Pair Programming Copilot)，協同實現 Golden Macro 解析引擎、三級深度法醫會診、多指令切割器與前端玻璃擬態控制台。
* 承襲 `PacketScope`、`NetScope`、`SwitchScope` 與 `vlan-web-portal` 之維運工具矩陣，專注解決地端現場網管與雲原生工程師的核心痛點。

---

## ⚠️ 免責聲明 (Disclaimer)

> 其他環境與發行版沒測過，只用 AI 測過，就好 XD。實務環境請先於測試叢集驗證修復指令與回滾流程。

---

## 📄 License
MIT License. 歡迎自由修改、分發與用於企業內部維運。
