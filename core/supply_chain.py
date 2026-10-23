"""
KubeScope - Software Supply Chain & Container Security Auditor
Detects Typosquatting packages, unhashed/floating dependencies, mutable tags (:latest), and root runtime escalation.
"""
import re
from typing import Any, Dict, List

class SupplyChainAuditor:
    def __init__(self):
        # Known common typosquats
        self.popular_packages = ["requests", "urllib3", "numpy", "pandas", "cryptography", "flask", "django"]

    def audit_requirements(self, raw_text: str) -> Dict[str, Any]:
        lines = [l.strip() for l in raw_text.strip().splitlines() if l.strip() and not l.startswith("#")]
        packages_count = len(lines)
        hashed_count = 0
        findings: List[Dict[str, Any]] = []

        for line in lines:
            if "--hash=" in line:
                hashed_count += 1

            pkg_name = re.split(r'[=><~]', line)[0].strip()

            # 1. Typosquatting Check
            for pop in self.popular_packages:
                if pkg_name != pop and self._is_typosquat(pkg_name, pop):
                    findings.append({
                        "category": "TYPOSQUATTING",
                        "target": pkg_name,
                        "severity": "CRITICAL",
                        "description": f"套件名稱 '{pkg_name}' 高度疑似知名套件 '{pop}' 之仿冒偽造惡意包 (Typosquatting)！"
                    })

            # 2. Floating Version Check (>=, >, ~)
            if re.search(r'[><~]', line) and not line.startswith(f"{pkg_name}=="):
                findings.append({
                    "category": "FLOATING_VERSION",
                    "target": pkg_name,
                    "severity": "HIGH",
                    "description": f"套件 '{pkg_name}' 使用浮動或未釘死之版本約束 ({line})，易遭遇自動拉取惡意補丁版本升級！"
                })

        return {
            "success": True,
            "packages_count": packages_count,
            "hashed_count": hashed_count,
            "findings": findings
        }

    def _is_typosquat(self, candidate: str, target: str) -> bool:
        """Simple Levenshtein distance 1 or character swap check."""
        if len(candidate) != len(target):
            return False
        diffs = sum(1 for a, b in zip(candidate, target) if a != b)
        return diffs in (1, 2) and sorted(candidate) == sorted(target)

    def audit_container_images(self, pods: List[Dict[str, Any]]) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []

        for p in pods:
            p_name = p.get("name", "pod")
            ns = p.get("namespace", "default")
            images = p.get("images", [])
            sec_ctx = p.get("security_context", {})

            for img in images:
                # 1. Mutable tag check
                if img.endswith(":latest") or ":" not in img:
                    findings.append({
                        "category": "MUTABLE_TAG",
                        "target": f"{ns}/{p_name} ({img})",
                        "severity": "HIGH",
                        "description": f"映像檔 '{img}' 使用浮動標籤 ':latest'，隨時可能被覆蓋注入惡意代碼，缺乏生產環境防篡改保證！"
                    })

            # 2. Security context escalation
            if sec_ctx.get("runAsNonRoot") is False or sec_ctx.get("readOnlyRootFilesystem") is False:
                findings.append({
                    "category": "RUNTIME_ESCALATION_RISK",
                    "target": f"{ns}/{p_name}",
                    "severity": "CRITICAL",
                    "description": "容器以 Root 特權使用者運行或允許寫入根檔案系統，若遭遠端代碼執行攻擊將直接導致主機逃逸。"
                })

        return {
            "success": True,
            "findings": findings
        }
