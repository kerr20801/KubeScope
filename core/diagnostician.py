"""
KubeScope - Kubernetes Cluster Diagnostician & Forensic Engine
Identifies Pod crashes, OOMKilled, Service selector mismatches, Evictions, and blackholes.
"""
from typing import Any, Dict, List

class KubeDiagnostician:
    def __init__(self):
        pass

    def diagnose_cluster(self, cluster_model: Dict[str, Any]) -> Dict[str, Any]:
        pods = cluster_model.get("pods", [])
        nodes = cluster_model.get("nodes", [])
        services = cluster_model.get("services", [])
        events = cluster_model.get("events", [])

        issues: List[Dict[str, Any]] = []

        # 1. Diagnose Nodes
        healthy_nodes = 0
        for n in nodes:
            is_ready = n.get("is_healthy", True)
            if "NotReady" in n.get("status", ""):
                is_ready = False
            if is_ready:
                healthy_nodes += 1
            else:
                issues.append({
                    "id": f"NODE_NOT_READY_{n.get('name')}",
                    "category": "NODE_NOT_READY",
                    "title": f"【節點脫機】節點 {n.get('name')} 處於 NotReady 異常狀態",
                    "target": n.get("name", "unknown-node"),
                    "severity": "CRITICAL",
                    "cause": "Kubelet 心跳中斷、磁碟壓力 (DiskPressure) 或網路 CNI 異常。",
                    "log_snippet": "",
                    "recommendation": "請於跳板機執行檢查 Kubelet 服務狀態與系統資源日誌。",
                    "actionable_commands": [
                        f"kubectl describe node {n.get('name')}",
                        f"ssh {n.get('internal_ip', n.get('name'))} 'journalctl -u kubelet -n 100 --no-pager'"
                    ]
                })

        # 2. Diagnose Pods
        critical_pods = 0
        warning_pods = 0
        healthy_pods = 0

        for p in pods:
            pod_issues = self._diagnose_single_pod(p, cluster_model)
            if any(i.get("severity") == "CRITICAL" for i in pod_issues):
                critical_pods += 1
            elif any(i.get("severity") == "WARNING" for i in pod_issues):
                warning_pods += 1
            else:
                healthy_pods += 1

            issues.extend(pod_issues)

        # 3. Diagnose Services & Selector Mismatches
        for svc in services:
            svc_name = svc.get("name", "")
            svc_ns = svc.get("namespace", "default")
            selector = svc.get("selector", {})
            endpoints = svc.get("endpoints", [])

            # Check if selector matches zero pods or has empty endpoints
            matched_pods = 0
            if selector:
                for p in pods:
                    if p.get("namespace", "default") == svc_ns:
                        p_labels = p.get("labels", {})
                        if all(p_labels.get(k) == v for k, v in selector.items()):
                            matched_pods += 1

            if selector and matched_pods == 0:
                issues.append({
                    "id": f"SVC_BLACKHOLE_{svc_ns}_{svc_name}",
                    "category": "NETWORK_BLACKHOLE",
                    "title": f"【服務黑洞】Service {svc_name} 標籤選擇器懸空無對應 Pod",
                    "target": f"{svc_ns}/{svc_name}",
                    "severity": "CRITICAL",
                    "cause": f"Service 宣告選擇器 selector={selector}，但在 {svc_ns} 命名空間內無任何 Pod 符合此 Label，導致 Endpoints 為空，請求陷入黑洞 (503/Connection Refused)。",
                    "log_snippet": f"Service Selector: {selector} | Matched Pods: 0",
                    "recommendation": "請比對 Deployment / Pod 的 labels 與 Service selector 定義，修正拼字或名稱錯配。",
                    "actionable_commands": [
                        f"kubectl get svc -n {svc_ns} {svc_name} -o yaml",
                        f"kubectl get pods -n {svc_ns} --show-labels"
                    ]
                })

        # Compute cluster health score (0-100)
        deduction = (critical_pods * 20) + (warning_pods * 8) + (len([i for i in issues if i.get("category") == "NETWORK_BLACKHOLE"]) * 25)
        health_score = max(0, 100 - deduction)

        return {
            "health_score": health_score,
            "stats": {
                "total_pods": len(pods),
                "healthy_pods": healthy_pods,
                "critical_pods": critical_pods,
                "warning_pods": warning_pods,
                "total_nodes": len(nodes),
                "healthy_nodes": healthy_nodes
            },
            "issues": issues
        }

    def _diagnose_single_pod(self, pod: Dict[str, Any], cluster_model: Dict[str, Any]) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        name = pod.get("name", "unknown")
        ns = pod.get("namespace", "default")
        status = pod.get("status", pod.get("status_reason", ""))
        target = f"{ns}/{name}"
        restarts = pod.get("restarts", 0)

        # 1. OOMKilled
        if "OOMKilled" in status or pod.get("last_termination_reason") == "OOMKilled" or pod.get("exit_code") == 137:
            limits = pod.get("limits", {})
            issues.append({
                "id": f"POD_OOM_{ns}_{name}",
                "category": "OOMKILLED",
                "title": f"【記憶體溢位】Pod {name} 觸發 OOMKilled (Exit Code 137)",
                "target": target,
                "severity": "CRITICAL",
                "cause": f"容器消耗記憶體突破宣告之上限 (Memory Limit: {limits.get('memory', '未指定')})，遭 Linux 核心 cgroup OOM Killer 強制 SIGKILL 擊殺。",
                "log_snippet": "java.lang.OutOfMemoryError: Java heap space\nContainer terminated with exit code 137 (SIGKILL / OOMKilled)",
                "recommendation": "請適度調高 resources.limits.memory 額度，或排查程式記憶體洩漏 (Memory Leak)。",
                "actionable_commands": [
                    f"kubectl describe pod -n {ns} {name} | grep -A 5 -B 5 -i oom",
                    f"kubectl logs -n {ns} {name} --previous --tail=100"
                ]
            })

        # 2. CrashLoopBackOff
        elif "CrashLoopBackOff" in status and not status.startswith("Init:"):
            issues.append({
                "id": f"POD_CRASH_{ns}_{name}",
                "category": "CRASHLOOP",
                "title": f"【應用高頻崩潰】Pod {name} 陷入 CrashLoopBackOff",
                "target": target,
                "severity": "CRITICAL",
                "cause": f"容器主進程啟動後異常退出 (累計重啟 {restarts} 次)，Kubelet 指數退避延遲拉長，通常由缺少設定檔、資料庫連線拒絕或代碼 Panic 引發。",
                "log_snippet": f"Last exit reason: CrashLoopBackOff | Restarts: {restarts}",
                "recommendation": "使用 --previous 旗標調閱上一代容器死前最後 200 行日誌以精準鎖定崩潰原因。",
                "actionable_commands": [
                    f"kubectl logs -n {ns} {name} --previous --tail=200",
                    f"kubectl describe pod -n {ns} {name}"
                ]
            })

        # 3. Init Container Blocked
        if status.startswith("Init:") or "Init:" in pod.get("status_reason", ""):
            issues.append({
                "id": f"POD_INIT_BLOCKED_{ns}_{name}",
                "category": "INIT_CONTAINER_BLOCKED",
                "title": f"【前置容器阻斷】Pod {name} 卡在初始化階段 ({status})",
                "target": target,
                "severity": "CRITICAL",
                "cause": "InitContainer (如資料庫結構遷移 migration、等待相依服務就緒) 執行失敗或崩潰，導致業務主容器永遠無法開始啟動。",
                "log_snippet": f"Status: {status} | Restarts: {restarts}",
                "recommendation": "指定 -c 參數針對 Init 容器專屬提取日誌查看阻斷根因。",
                "actionable_commands": [
                    f"kubectl get pod -n {ns} {name} -o jsonpath='{{.spec.initContainers[*].name}}'",
                    f"kubectl logs -n {ns} {name} -c <init-container-name> --tail=200"
                ]
            })

        # 4. Evicted
        if "Evicted" in status or pod.get("status_reason") == "Evicted":
            issues.append({
                "id": f"POD_EVICTED_{ns}_{name}",
                "category": "EVICTED_POD",
                "title": f"【遭節點驅逐】Pod {name} 處於 Evicted 驅逐殘留狀態",
                "target": target,
                "severity": "CRITICAL",
                "cause": "該節點觸發資源驅逐門檻 (如 DiskPressure 磁碟空間耗盡、MemoryPressure 記憶體耗盡)，Kubelet 強行驅逐該 Pod。",
                "log_snippet": "The node had condition: [DiskPressure/MemoryPressure]. Evicted pod.",
                "recommendation": "清理主機磁碟空間，並使用安全指令批次清除 Evicted 垃圾狀態釋放 APIServer 負擔。",
                "actionable_commands": [
                    f"kubectl get pods -n {ns} --field-selector status.phase=Failed -o jsonpath='{{.items[?(@.status.reason==\"Evicted\")].metadata.name}}'",
                    f"kubectl delete pods -n {ns} --field-selector status.phase=Failed"
                ]
            })

        # 5. ImagePullBackOff / ErrImagePull
        if "ImagePull" in status or "ErrImage" in status:
            issues.append({
                "id": f"POD_IMAGE_PULL_{ns}_{name}",
                "category": "IMAGE_PULL_FAILED",
                "title": f"【映像檔拉取失敗】Pod {name} ({status})",
                "target": target,
                "severity": "CRITICAL",
                "cause": "映像檔名稱/Tag 拼錯、Docker Registry 權杖過期 (imagePullSecrets 缺失) 或機房網路無法連通倉庫。",
                "log_snippet": f"Status: {status}",
                "recommendation": "檢查映像檔路徑拼寫與 imagePullSecrets 密鑰宣告。",
                "actionable_commands": [
                    f"kubectl describe pod -n {ns} {name} | grep -A 5 -i failed"
                ]
            })

        return issues
