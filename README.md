# ⬡ KubeScope — Kubernetes 異常透視與白話排障軍師

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011%20%7C%20Server-lightgrey.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Zero-Agent](https://img.shields.io/badge/Zero--Agent-100%25%20In--Cluster%20Free-emerald.svg)]()
[![Air-Gapped](https://img.shields.io/badge/Privacy-100%25%20Air--Gapped%20Local-success.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

專為**網路工程師、系統管理員 (SysAdmin)、初入 K8s 的開發者與機房維運人員**打造的**輕量零侵入 Kubernetes 異常透視、CVE 漏洞快篩與升級導引軍師**！  
**100% 純唯讀、免在叢集安裝任何 Agent / CRD、支援無網斷網機房（Air-Gapped）、拒絕黑盒子自走砲（Human-in-the-Loop）。**

---

## 🌟 解決什麼核心痛點？

在維護 Kubernetes 叢集時，非專職 K8s SRE 的工程師經常面臨四大崩潰折磨：

1. **資訊海嘯，只報紅燈卻不說「人話」**：
   * 像 Lens 或 k9s 只是將 YAML 與狀態平鋪在畫面上。看到一個紅色的 `CrashLoopBackOff`、`OOMKilled` 或 `Pending`，多數人根本不知道背後到底發生了什麼事，更不知道「下一步該下哪條指令」。
2. **生產機房嚴禁在叢集內裝東裝西**：
   * 大多數商業或進階監控工具非得在叢集裡用 Helm 裝一大堆 DaemonSet、Operator 與特權 CRD。在客戶機房或企業嚴格環境下，**資安絕對不放行，也拿不到 cluster-admin 授權**。
3. **沒有人敢讓 AI 自動亂改生產環境**：
   * 某些自走砲 AI Agent 標榜「自動修復 K8s」，但在正式營運環境，**沒有任何維運人員敢讓 AI 自主執行 `kubectl delete/patch`**！
   * 現場真正需要的是：**「白話剖析病因 ➔ 提取精準 5 行關鍵日誌 ➔ 產出安全可驗證的指令由工程師複製執行」的 SRE 隨身軍師 (Copilot, not Autopilot)**！
4. **升版恐懼症與資安 CVE 盲區**：
   * 很多人不知道 K8s 官方僅支援 N ➔ N+1 升級，跨版直升會導致叢集毀滅性癱瘓。
   * 不清楚自己的 K8s 版本是否暴露在重大 CVE (如 Kubelet 越權掛載、指令注入)，也不知道有哪些舊版 API (如 PSP、v1beta1 Ingress) 在新版已被強制刪除。

---

## 🚀 六大核心功能模組矩陣

### 模組 1：🧭 實戰排障操作流四部曲 (Interactive Troubleshooting Workbench ⭐ 首推)
專為實際在跳板機終端機排查故障的工程師設計，手把手引導你完成標準 SRE 排查流程：
* **第 1 動：檢查節點健康度 (`kubectl get nodes -o wide`)**：
  * 解析每台節點的 Ready 狀態、OS 系統與 Kubelet 版本。
* **第 2 動：篩查命名空間 Pods (`kubectl get pods -A -o wide`)**：
  * 貼上終端機文字表格，自動標示 🟢 正常、🔴 CrashLoopBackOff / Error、🟡 Pending、**`Init:0/1` 卡死、`Evicted` 殘留**。
  * **點擊異常 Pod**，系統自動鎖定為取證目標！
* **第 3 動：智能組裝取證指令 (Fetch Logs & Describe)**：
  * 🔑 **撈取死亡遺言 (90% 人都不知道)**：`kubectl logs -n <ns> <pod> --previous --tail=200`
  * 🔑 **InitContainer 卡死撈取**：`kubectl logs -n <ns> <pod> -c <init-container>`
  * 📜 **撈取目前即時日誌**：`kubectl logs -n <ns> <pod> --tail=200`
  * 🔍 **查看 Kubelet 探針與調度事件**：`kubectl describe pod -n <ns> <pod>`
* **第 4 動：日誌深度法醫與白話翻譯 (Log Forensic Analyzer)**：
  * **致命錯誤切片**：過濾幾萬行 INFO 心跳，只提取致命 Panic、OOM 137、DB 連線拒絕、缺少設定檔。
  * **說人話（白話翻譯）**：告訴你背後發生了什麼事，並直接附上可複製的驗證與修復指令！

### 模組 2：🌐 全鏈路路由拓撲透視 (Traffic Route Tracer ⭐ 網管工程師必備)
徹底解決「服務打不通、回傳 502 Bad Gateway 或 503 Service Unavailable，卻不知道斷在哪一層」的惡夢：
* **五層流量拓撲鏈**：
  `Client 請求 ➔ Ingress (域名/路徑) ➔ Service (端口/選擇器) ➔ Endpoints (就緒實體) ➔ Pods (容器埠號/探針)`
* **精準定位斷鏈層級**：
  * ❌ **Ingress 懸空**：Ingress 指向不存在的 Service (404/503)。
  * ❌ **Service 端口衝突**：Ingress 要求的 port 在 Service 中未宣告 (502/503)。
  * ❌ **標籤選擇器懸空**：Service selector 與 Pod labels 不吻合，Endpoints 為空 (503)。
  * ❌ **探針失敗踢除**：Pod 存在但 Readiness 就緒探針未通過，遭 Endpoints 全數下線 (503)。
  * ❌ **埠號設定衝突**：Service targetPort 與 Pod 實際監聽埠號不一致 (502 Connection Refused)。

### 模組 3：🔐 控制面憑證、KubeAPI 探針與 IPAM 健檢 (Infra Doctor ⭐)
* **Kubeadm 控制平面 PKI 憑證壽命審計 (`kubeadm certs check-expiration`)**：
  * 查驗 `admin.conf`、`apiserver`、`etcd-peer`、`kubelet-client` 等所有內部憑證。
  * 警示已過期（全叢集拒絕連線）或 30 天內臨期憑證，並提供一鍵更新更新指令（`kubeadm certs renew all`）。
* **Kube-APIServer `/readyz` 深度狀態剖析**：
  * 深度檢驗 etcd 寫入延遲逾時 (>100ms)、Webhook 卡死阻塞、API 限流。
* **IP / CIDR / CNI 子網耗盡與 CoreDNS 常備排障清單**：
  * 節點 Pod CIDR 額度風險評估 (防範 CNI 拋出 `no IP addresses available in range`)。
  * CoreDNS 崩潰排查與 `ndots:5` 延遲陷阱避坑指南。

### 模組 4：🛡️ K8s 版本與組件 CVE 漏洞掃描儀 (CVE Security Scanner)
* **內建 Air-Gapped 離線高危 CVE 資料庫**：
  * 涵蓋 K8s 歷史重大漏洞：CVE-2024-3177、CVE-2023-5528、CVE-2023-3676、CVE-2023-2727、CVE-2022-3172、CVE-2021-25741 等。
* **智慧版本比對**：
  * 自動比對當前或自訂 K8s 版本，輸出受影響漏洞清單、CVSS 風險評分與官方建議修補版本。

### 模組 5：🗺️ 升版教學與平滑導航儀 (Upgrade Advisor & Playbook)
* **跨版本跳級防呆 (Version Hopping Guard)**：
  * 自動推算多階段升級路徑（例如：`v1.24.2 ➔ v1.25.16 ➔ v1.26.15 ➔ v1.27.0`），禁止跨版直升！
* **已廢棄 API 移除預警 (API Deprecation Audit)**：
  * 偵測目標版本移除的廢棄 API（如 v1.25 移除 PSP），提供 Before/After 的 YAML 遷移對照範例。
* **逐步操作手冊 (Step-by-Step Runbook)**：
  * 完整支援 **`kubeadm`**、**`RKE2`**、**`K3s`** 三大主流工具鏈，提供每一步驟的一鍵複製指令。

### 模組 6：🤖 本地 SRE 隨身軍師 (AI Copilot with Local Ollama & Qwen 3.5)
* **100% 機敏資料不出機房**：
  * 自動串接地端運行的 **Ollama**，原生支援新一代 **Qwen 3.5 (256K 超長上下文，支援多模態文字與架構圖)**。
  * **純 CPU 無顯卡也能跑**：
    * `qwen3.5:0.8b` (1.2G~1.3G) ➔ 純 CPU 筆電毫秒秒回！
    * `qwen3.5:2b` (2.7G~3.1G) ➔ 輕量維運機純 CPU 首選 (25~35 tokens/s)！
    * `qwen3.5:4b` (3.3G~4.0G) ➔ 推理深度與速度的極佳平衡！
    * `qwen3.5:latest` (9B 旗艦，6.6G~7.6G) ➔ SRE 首選 (建議 8G+ 顯卡或 16G+ 記憶體)！
* **內建離線專家決策樹**：
  * 若無安裝 Ollama 或不想跑模型，系統自動啟用內建 SRE 離線專家庫，依舊能針對各類事故提供白話解析與安全指令！

---

## 📁 專案架構

```text
KubeScope/
  ├── core/
  │    ├── parser.py           # K8s 表格、describe 與日誌文字正則剖析器
  │    ├── route_tracer.py     # 全鏈路路由拓撲 (Ingress➔Service➔Endpoints➔Pods) 透視
  │    ├── infra_doctor.py     # 憑證到期審計、KubeAPI 探針、PodCIDR 耗盡與 CoreDNS
  │    ├── log_analyzer.py     # 深度日誌法醫、致命錯誤行切片與白話翻譯引擎
  │    ├── diagnostician.py    # Pod 深度法醫(Init/探針/Evicted)、流量黑洞與反模式引擎
  │    ├── cve_scanner.py      # K8s 離線 CVE 漏洞庫與語意版本比對引擎
  │    ├── upgrade_advisor.py  # 升級路徑推算、廢棄 API 預警與逐步 Runbook 生成
  │    └── llm_gateway.py      # 地端 Ollama 串接與離線 SRE 專家決策庫
  ├── web/
  │    └── index.html          # 現代化純前端深色面板 (交通燈儀表板 + CVE + 升級導航 + AI 對話)
  ├── samples/
  │    ├── sample_cluster_issues.json   # 實戰綜合故障事故範例 (OOM + Crash + 服務黑洞)
  │    ├── sample_healthy_cluster.json  # 正常健康叢集 (100分演示)
  │    └── sample_cve_legacy.json       # 老舊叢集 (含 CVE 與廢棄 API 樣本)
  ├── server.py                # 零依賴 Python RESTful API 伺服器 (埠號 8930)
  ├── test_engine.py           # 自動化迴歸測試套件 (涵蓋法醫診斷、CVE、升級推算)
  ├── launcher.ps1             # 智慧環境檢查與快速啟動腳本
  ├── 啟動服務.bat              # Windows 雙擊極速啟動 (自動開啟瀏覽器)
  ├── requirements.txt         # 零強制外部依賴 (純 Python 3.10+ 標準庫即可運行)
  ├── LICENSE                  # MIT 開源授權協議
  └── README.md                # 專案詳細說明文件
```

---

## 🚀 快速開始
 
1. 雙擊執行目錄中的 **`啟動服務.bat`**。
2. 預設瀏覽器會自動開啟控制台：`http://localhost:8930/`。
3. 體驗 **「🧭 實戰排障操作流」**：
   * 點擊 **「第 1 動：檢測節點健康」** 貼上 `kubectl get nodes -o wide` 或直接點「載入範例」。
   * 點擊 **「第 2 動：篩查命名空間 Pods」** 貼上 `kubectl get pods -A -o wide`，點選紅色故障 Pod。
   * **「第 3 動：智能神鑰匙」** 自動生成死亡遺言指令（`kubectl logs --previous`），複製並貼入終端機。
   * 將日誌貼入 **「第 4 動：日誌深度法醫」**，秒得白話病因與安全修復指令！
4. 切換至 **`🛡️ K8s CVE 漏洞掃描`** 或 **`🗺️ 升版教學與平滑導引`** 體驗專案級維運工具的威力！
5. **想啟用在地 SRE 軍師 (選配)**：
   * 安裝 Ollama：`winget install Ollama.Ollama`
   * 啟動 Qwen 3.5 (純 CPU 推薦 2B，有顯卡或記憶體夠推薦 latest/9B)：
     ```bash
     ollama run qwen3.5:latest
     # 或純 CPU 筆電無顯卡：
     ollama run qwen3.5:2b
     ```
   * 介面點擊「重新檢測連線」，立即與 SRE 軍師多輪深度對談！即使不安裝 Ollama，KubeScope 依然具備完整離線專家決策庫隨時運作。

---

## 👨‍💻 作者 (Author)

* **Kerr** ([@kerr20801](https://github.com/kerr20801))
* 承襲 `PacketScope`、`NetScope`、`SwitchScope` 與 `vlan-web-portal` 之維運工具矩陣，專注解決地端現場網管與雲原生工程師的核心痛點。

---

## 📄 License
MIT License. 歡迎自由修改、分發與用於企業內部維運。
