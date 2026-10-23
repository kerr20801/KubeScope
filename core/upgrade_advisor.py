"""
KubeScope - Kubernetes Multi-Hop Upgrade Advisor & Runbook Generator
Enforces N -> N+1 version progression, audits removed/deprecated APIs, and synthesizes copy-pasteable runbooks.
"""
import re
from typing import Any, Dict, List, Tuple

class UpgradeAdvisor:
    def __init__(self):
        # Database of deprecated and removed APIs across Kubernetes minor versions
        self.deprecations_db: Dict[str, List[Dict[str, str]]] = {
            "v1.25": [
                {
                    "api": "policy/v1beta1 PodSecurityPolicy (PSP)",
                    "removed_in": "v1.25",
                    "replacement": "Pod Security Standards (PSS) / admission labels (pod-security.kubernetes.io/enforce)",
                    "action": "在升級至 1.25 前，必須全面替換 PSP，改用命名空間標籤宣告 Privileged/Baseline/Restricted 安全規範。"
                },
                {
                    "api": "batch/v1beta1 CronJob",
                    "removed_in": "v1.25",
                    "replacement": "batch/v1 CronJob",
                    "action": "將所有 CronJob YAML 的 apiVersion: batch/v1beta1 更新為 batch/v1。"
                },
                {
                    "api": "discovery.k8s.io/v1beta1 EndpointSlice",
                    "removed_in": "v1.25",
                    "replacement": "discovery.k8s.io/v1 EndpointSlice",
                    "action": "改用 discovery.k8s.io/v1 正式版 API。"
                }
            ],
            "v1.26": [
                {
                    "api": "autoscaling/v2beta2 HorizontalPodAutoscaler (HPA)",
                    "removed_in": "v1.26",
                    "replacement": "autoscaling/v2 HorizontalPodAutoscaler",
                    "action": "將 HPA YAML apiVersion 更新為 autoscaling/v2。"
                },
                {
                    "api": "flowcontrol.apiserver.k8s.io/v1beta1 FlowSchema",
                    "removed_in": "v1.26",
                    "replacement": "flowcontrol.apiserver.k8s.io/v1 FlowSchema",
                    "action": "更新 FlowSchema 與 PriorityLevelConfiguration 物件宣告。"
                }
            ],
            "v1.27": [
                {
                    "api": "storage.k8s.io/v1beta1 CSIStorageCapacity",
                    "removed_in": "v1.27",
                    "replacement": "storage.k8s.io/v1 CSIStorageCapacity",
                    "action": "升級 CSI 儲存驅動程式至正式版相容版本。"
                }
            ]
        }

    def _parse_semver(self, ver_str: str) -> Tuple[int, int, int]:
        clean = re.sub(r'^[^\d]*', '', ver_str.strip())
        parts = clean.split('.')
        major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 1
        minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 24
        patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        return (major, minor, patch)

    def plan_upgrade(self, current_ver: str, target_ver: str, toolchain: str = "kubeadm") -> Dict[str, Any]:
        cur_maj, cur_min, cur_pat = self._parse_semver(current_ver)
        tar_maj, tar_min, tar_pat = self._parse_semver(target_ver)

        if (tar_maj < cur_maj) or (tar_maj == cur_maj and tar_min < cur_min):
            return {
                "success": False,
                "error": f"目標版本 ({target_ver}) 低於當前版本 ({current_ver})，K8s 官方不支援降級！"
            }

        hops: List[str] = []
        c_min = cur_min
        while c_min < tar_min:
            c_min += 1
            hops.append(f"v{cur_maj}.{c_min}.0")

        hop_count = len(hops)
        need_multihop = hop_count > 1

        # Collect removed and deprecated APIs along the upgrade path
        deprecations: List[Dict[str, str]] = []
        for m in range(cur_min + 1, tar_min + 1):
            key = f"v{cur_maj}.{m}"
            if key in self.deprecations_db:
                deprecations.extend(self.deprecations_db[key])

        # Synthesize step-by-step Runbook
        runbook = self._generate_runbook(current_ver, target_ver, hops, toolchain)

        return {
            "success": True,
            "current_version": current_ver,
            "target_version": target_ver,
            "toolchain": toolchain,
            "need_multihop": need_multihop,
            "hop_count": hop_count,
            "upgrade_hops": hops,
            "deprecations": deprecations,
            "runbook": runbook
        }

    def _generate_runbook(self, cur: str, tar: str, hops: List[str], toolchain: str) -> List[Dict[str, str]]:
        steps: List[Dict[str, str]] = [
            {
                "step": "1. 災難還原前置：備份 etcd 叢集狀態資料庫",
                "description": "升級前必須對 control-plane 節點執行完整 etcd 快照，防止控制面版本升級崩潰時無可挽回。",
                "command": "ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/server.crt --key=/etc/kubernetes/pki/etcd/server.key snapshot save /tmp/etcd-backup-preupgrade.db"
            },
            {
                "step": "2. 驗證快照完整性",
                "description": "檢查快照檔案狀態與 hash 校驗碼。",
                "command": "ETCDCTL_API=3 etcdctl --write-out=table snapshot status /tmp/etcd-backup-preupgrade.db"
            }
        ]

        if toolchain.lower() == "kubeadm":
            for idx, hop in enumerate(hops, 1):
                steps.append({
                    "step": f"3.{idx} 階段升級至 {hop} (嚴格遵循 N ➔ N+1)",
                    "description": f"升級 control-plane kubeadm 工具並套用 {hop} 叢集升版宣告：",
                    "command": (
                        f"# 1. 驅逐排程\nkubectl drain <cp-node> --ignore-daemonsets\n\n"
                        f"# 2. 更新套件\napt-mark unhold kubeadm && apt-get update && apt-get install -y kubeadm={hop.replace('v', '')}-00 && apt-mark hold kubeadm\n\n"
                        f"# 3. 升版計畫審計\nkubeadm upgrade plan\n\n"
                        f"# 4. 正式套用升版\nkubeadm upgrade apply {hop}\n\n"
                        f"# 5. 升級 Kubelet\napt-mark unhold kubelet kubectl && apt-get install -y kubelet={hop.replace('v', '')}-00 kubectl={hop.replace('v', '')}-00 && apt-mark hold kubelet kubectl\n\n"
                        f"# 6. 重啟服務並解除排程鎖定\nsystemctl daemon-reload && systemctl restart kubelet\nkubectl uncordon <cp-node>"
                    )
                })

        return steps
