"""
KubeScope - Air-Gapped Kubernetes Offline CVE Vulnerability Scanner
"""
import re
from typing import Any, Dict, List, Tuple

class CVEScanner:
    def __init__(self):
        # Comprehensive curated Air-Gapped CVE vulnerability database
        self.cve_db: List[Dict[str, Any]] = [
            {
                "id": "CVE-2023-3676",
                "title": "Kubelet Windows 節點特權指令注入漏洞",
                "severity": "CRITICAL",
                "cvss": 8.8,
                "affected_ranges": [
                    ("v1.24.0", "v1.24.15"),
                    ("v1.25.0", "v1.25.11"),
                    ("v1.26.0", "v1.26.6"),
                    ("v1.27.0", "v1.27.3"),
                ],
                "description": "攻擊者可透過特定構造的 Pod 註解或磁碟掛載路徑，在 Windows 節點 Kubelet 上提權並執行任意命令。",
                "fixed_versions": ["v1.24.16", "v1.25.12", "v1.26.7", "v1.27.4"],
                "mitigation": "升級 Kubelet 與控制面版本至補丁版，或限制 Windows 節點使用者建立自訂掛載路徑。"
            },
            {
                "id": "CVE-2024-3177",
                "title": "Bypass subpath 越權掛載與主機逃逸漏洞",
                "severity": "HIGH",
                "cvss": 7.5,
                "affected_ranges": [
                    ("v1.25.0", "v1.27.14"),
                    ("v1.28.0", "v1.28.9"),
                    ("v1.29.0", "v1.29.4"),
                ],
                "description": "當 Pod 啟用 subPath 掛載時，惡意使用者可透過符號連結 (Symlink) 繞過目錄邊界存取主機節點敏感檔案。",
                "fixed_versions": ["v1.27.15", "v1.28.10", "v1.29.5"],
                "mitigation": "停用非必要之 subPath 掛載，或更新 Kubelet 二進位執行檔。"
            },
            {
                "id": "CVE-2023-5528",
                "title": "In-tree 儲存卷外掛本機特權越權存取",
                "severity": "HIGH",
                "cvss": 7.2,
                "affected_ranges": [
                    ("v1.24.0", "v1.26.10"),
                    ("v1.27.0", "v1.27.7"),
                    ("v1.28.0", "v1.28.3"),
                ],
                "description": "Windows 節點之本機儲存外掛存在權限校驗不當，具備普通建立權限的使用者可掛載並竄改任意磁區。",
                "fixed_versions": ["v1.26.11", "v1.27.8", "v1.28.4"],
                "mitigation": "升級修補版本，並全面改用外部 CSI 驅動外掛。"
            },
            {
                "id": "CVE-2022-3172",
                "title": "Aggregated API Server 伺服器端請求偽造 (SSRF)",
                "severity": "HIGH",
                "cvss": 7.7,
                "affected_ranges": [
                    ("v1.22.0", "v1.24.4"),
                    ("v1.25.0", "v1.25.0"),
                ],
                "description": "惡意註冊之聚合 API 伺服器可誘導 Kube-APIServer 向內部網路發起非預期的 HTTP 請求洩漏機敏資料。",
                "fixed_versions": ["v1.24.5", "v1.25.1"],
                "mitigation": "嚴格稽核 APIService 資源物件建立權限。"
            },
            {
                "id": "CVE-2021-25741",
                "title": "符號連結目錄穿越掛載逃逸",
                "severity": "HIGH",
                "cvss": 8.1,
                "affected_ranges": [
                    ("v1.20.0", "v1.21.4"),
                    ("v1.22.0", "v1.22.1"),
                ],
                "description": "在 Pod 初始化期間以符號連結替換路徑，使容器取得主機節點 Root 檔案系統讀寫存取。",
                "fixed_versions": ["v1.21.5", "v1.22.2"],
                "mitigation": "啟用 PodSecurityStandards Restricted 規範。"
            },
            {
                "id": "CVE-2018-1002105",
                "title": "Kubernetes API Server 特權提升與遠端代碼執行 (神級漏洞)",
                "severity": "CRITICAL",
                "cvss": 9.8,
                "affected_ranges": [
                    ("v1.0.0", "v1.10.10"),
                    ("v1.11.0", "v1.11.4"),
                    ("v1.12.0", "v1.12.2"),
                ],
                "description": "攻擊者可經由未授權或低權限之 HTTP/2 升級代理連線直接向 Kubelet 或後端注入任意指令並取得叢集 root 支配權。",
                "fixed_versions": ["v1.10.11", "v1.11.5", "v1.12.3"],
                "mitigation": "此為歷史級致命漏洞，強烈建議立即升級至現代支援之主流 Kubernetes 版本。"
            }
        ]

    def _parse_semver(self, ver_str: str) -> Tuple[int, int, int]:
        """Parses 'v1.26.2' into (1, 26, 2)."""
        clean = re.sub(r'^[^\d]*', '', ver_str.strip())
        parts = clean.split('.')
        major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 1
        minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 26
        patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        return (major, minor, patch)

    def _is_version_in_range(self, target_ver: str, min_ver: str, max_ver: str) -> bool:
        t = self._parse_semver(target_ver)
        low = self._parse_semver(min_ver)
        high = self._parse_semver(max_ver)
        return low <= t <= high

    def scan_cluster_version(self, version_str: str) -> Dict[str, Any]:
        """Scans a given Kubernetes version against the offline CVE database."""
        vulnerabilities: List[Dict[str, Any]] = []

        for cve in self.cve_db:
            matched = False
            for r_min, r_max in cve.get("affected_ranges", []):
                if self._is_version_in_range(version_str, r_min, r_max):
                    matched = True
                    break

            if matched:
                vulnerabilities.append({
                    "id": cve["id"],
                    "title": cve["title"],
                    "severity": cve["severity"],
                    "cvss": cve["cvss"],
                    "description": cve["description"],
                    "fixed_versions": cve["fixed_versions"],
                    "mitigation": cve["mitigation"]
                })

        # Sort by CVSS descending
        vulnerabilities.sort(key=lambda x: x["cvss"], reverse=True)

        return {
            "scanned_version": version_str,
            "total_cves": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "has_critical": any(v["severity"] == "CRITICAL" for v in vulnerabilities)
        }
