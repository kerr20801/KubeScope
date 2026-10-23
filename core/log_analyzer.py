"""
KubeScope - Kubernetes Container Log Forensic & SRE Translator Engine
Filters noise, isolates fatal panics/OOMs/connection refused errors, and explains in plain Traditional Chinese.
"""
import re
from typing import Any, Dict, List

class LogAnalyzer:
    def __init__(self):
        pass

    def analyze_log(self, log_text: str, pod_name: str = "", namespace: str = "default") -> Dict[str, Any]:
        if not log_text or not log_text.strip():
            return {
                "success": False,
                "error": "日誌文字為空，無法進行分析",
                "matched_issues": []
            }

        lines = log_text.strip().splitlines()
        matched_issues: List[Dict[str, Any]] = []

        # 1. OutOfMemory / Exit 137
        if re.search(r'OutOfMemoryError|Java heap space|exit code 137|SIGKILL|OOMKilled', log_text, re.IGNORECASE):
            relevant_lines = [l for l in lines if re.search(r'OutOfMemory|heap|137|SIGKILL', l, re.IGNORECASE)]
            matched_issues.append({
                "id": "OOM_HEAP",
                "title": "【記憶體溢位擊殺】JVM 堆積或容器 cgroup 超標 (Exit Code 137)",
                "severity": "CRITICAL",
                "evidence_snippet": "\n".join(relevant_lines[:5]),
                "plain_explanation": f"應用程式因申請超過 JVM Heap 或容器配額，被 Linux 核心 OOM Killer 直接擊殺 (SIGKILL)。",
                "actionable_commands": [
                    f"kubectl describe pod -n {namespace} {pod_name} | grep -A 5 -B 5 -i oom",
                    f"kubectl logs -n {namespace} {pod_name} --previous --tail=200",
                    f"kubectl get pod -n {namespace} {pod_name} -o jsonpath='{{.spec.containers[*].resources}}'"
                ]
            })

        # 2. Database Connection Timeout / Refused
        if re.search(r'dial tcp.*(timeout|refused)|connect.*ECONNREFUSED|Connection refused', log_text, re.IGNORECASE):
            relevant_lines = [l for l in lines if re.search(r'dial tcp|timeout|refused|ECONNREFUSED', l, re.IGNORECASE)]
            matched_issues.append({
                "id": "DB_CONN_TIMEOUT",
                "title": "【資料庫/相依服務逾時中斷】TCP 連線建立失敗或網路阻斷",
                "severity": "CRITICAL",
                "evidence_snippet": "\n".join(relevant_lines[:5]),
                "plain_explanation": f"Pod 嘗試向後端資料庫或外部服務發起 TCP 交握失敗（逾時或連線拒絕），請檢查目標 IP/DNS 是否存活，或 NetworkPolicy 是否阻斷出口流量。",
                "actionable_commands": [
                    f"kubectl exec -it -n {namespace} {pod_name} -- nc -zv <target-host> <target-port> || echo '無法連通目標服務'",
                    f"kubectl get networkpolicies -n {namespace}"
                ]
            })

        # 3. Application Panic / Fatal Error
        if re.search(r'panic:|fatal error:|NullPointerException|Exception in thread "main"', log_text, re.IGNORECASE):
            relevant_lines = [l for l in lines if re.search(r'panic:|fatal|NullPointer|Exception in thread', l, re.IGNORECASE)]
            matched_issues.append({
                "id": "APP_PANIC",
                "title": "【代碼運行期崩潰】應用拋出未捕獲之致命異常 (Panic/Fatal)",
                "severity": "CRITICAL",
                "evidence_snippet": "\n".join(relevant_lines[:5]),
                "plain_explanation": "應用程式內部發生未攔截之空指針或代碼邏輯崩潰，導致主進程退出。",
                "actionable_commands": [
                    f"kubectl logs -n {namespace} {pod_name} --previous --tail=200"
                ]
            })

        # 4. Config / Secret Missing
        if re.search(r'no such file or directory|FileNotFoundException|failed to load config', log_text, re.IGNORECASE):
            relevant_lines = [l for l in lines if re.search(r'no such file|FileNotFound|config', l, re.IGNORECASE)]
            matched_issues.append({
                "id": "CONFIG_FILE_MISSING",
                "title": "【缺少設定檔或密鑰】ConfigMap / Secret 掛載遺失",
                "severity": "HIGH",
                "evidence_snippet": "\n".join(relevant_lines[:5]),
                "plain_explanation": "容器啟動時無法讀取預期的設定檔或金鑰，請確認 ConfigMap/Secret 是否已被刪除或路徑宣告錯誤。",
                "actionable_commands": [
                    f"kubectl describe pod -n {namespace} {pod_name} | grep -A 10 'Volumes:'",
                    f"kubectl get configmap,secret -n {namespace}"
                ]
            })

        return {
            "success": True,
            "pod_name": pod_name,
            "namespace": namespace,
            "total_lines_analyzed": len(lines),
            "matched_issues": matched_issues
        }
