"""
KubeScope - Kubernetes CLI Output & Structured Model Ingestion Parser
"""
import re
import json
from typing import Any, Dict, List

class KubeParser:
    def __init__(self):
        pass

    def parse_input(self, raw_input: Any) -> Dict[str, Any]:
        """
        Ingests either:
        1. A pre-structured dictionary.
        2. A JSON string.
        3. A multi-section raw text CLI dump (kubectl get nodes, get pods, describe, etc.)
        """
        if isinstance(raw_input, dict):
            model = dict(raw_input)
            if "version" not in model:
                model["version"] = self._detect_version_from_nodes(model.get("nodes", []))
            return model

        if isinstance(raw_input, str):
            trimmed = raw_input.strip()
            if trimmed.startswith("{") and trimmed.endswith("}"):
                try:
                    loaded = json.loads(trimmed)
                    if isinstance(loaded, dict):
                        if "version" not in loaded:
                            loaded["version"] = self._detect_version_from_nodes(loaded.get("nodes", []))
                        return loaded
                except Exception:
                    pass

            return self._parse_text_cli_dump(raw_input)

        return {"version": "v1.26.0", "nodes": [], "pods": [], "services": [], "events": []}

    def _detect_version_from_nodes(self, nodes: List[Dict[str, Any]]) -> str:
        for n in nodes:
            ver = n.get("version") or n.get("kubelet_version")
            if ver and ver.startswith("v"):
                return ver
        return "v1.26.0"

    def parse_nodes_table(self, raw_text: str) -> List[Dict[str, Any]]:
        """Parses `kubectl get nodes -o wide` or `kubectl get nodes` output."""
        lines = [line.strip() for line in raw_text.strip().splitlines() if line.strip()]
        if not lines:
            return []

        header_idx = -1
        for i, line in enumerate(lines):
            if "NAME" in line and "STATUS" in line and ("ROLES" in line or "VERSION" in line or "INTERNAL-IP" in line or "AGE" in line):
                header_idx = i
                break

        if header_idx == -1:
            return []

        nodes = []
        for line in lines[header_idx + 1:]:
            if line.startswith("$") or line.startswith(">") or "NAMESPACE" in line:
                break
            parts = re.split(r'\s{2,}|\t+', line)
            if len(parts) < 2:
                parts = line.split()
            if len(parts) < 2:
                continue

            name = parts[0]
            status = parts[1]
            roles = parts[2] if len(parts) > 2 else "worker"
            age = parts[3] if len(parts) > 3 else "unknown"
            version = parts[4] if len(parts) > 4 else "v1.26.0"
            internal_ip = parts[5] if len(parts) > 5 else ""
            os_image = parts[7] if len(parts) > 7 else ""
            kernel = parts[8] if len(parts) > 8 else ""
            runtime = parts[9] if len(parts) > 9 else ""

            is_ready = "Ready" in status and "NotReady" not in status
            nodes.append({
                "name": name,
                "status": status,
                "roles": roles,
                "age": age,
                "version": version,
                "internal_ip": internal_ip,
                "os_image": os_image,
                "kernel_version": kernel,
                "container_runtime": runtime,
                "is_healthy": is_ready
            })
        return nodes

    def parse_pods_table(self, raw_text: str) -> List[Dict[str, Any]]:
        """Parses `kubectl get pods -A -o wide` or `kubectl get pods` table."""
        lines = [line.strip() for line in raw_text.strip().splitlines() if line.strip()]
        if not lines:
            return []

        header_idx = -1
        has_namespace = False
        for i, line in enumerate(lines):
            if "NAME" in line and "STATUS" in line and ("READY" in line or "RESTARTS" in line):
                header_idx = i
                has_namespace = "NAMESPACE" in line
                break

        if header_idx == -1:
            return []

        pods = []
        for line in lines[header_idx + 1:]:
            if line.startswith("$") or line.startswith(">") or ("NAME" in line and "TYPE" in line):
                break
            parts = re.split(r'\s{2,}|\t+', line)
            if len(parts) < (4 if has_namespace else 3):
                parts = line.split()
            if len(parts) < (4 if has_namespace else 3):
                continue

            idx = 0
            namespace = parts[idx] if has_namespace else "default"
            if has_namespace:
                idx += 1

            name = parts[idx]
            ready = parts[idx + 1] if len(parts) > idx + 1 else "1/1"
            status = parts[idx + 2] if len(parts) > idx + 2 else "Unknown"
            restarts = parts[idx + 3] if len(parts) > idx + 3 else "0"
            age = parts[idx + 4] if len(parts) > idx + 4 else "unknown"
            ip = parts[idx + 5] if len(parts) > idx + 5 else ""
            node = parts[idx + 6] if len(parts) > idx + 6 else ""

            severity = self._evaluate_pod_severity(status, ready)
            is_healthy = severity == "NORMAL"

            restart_num = 0
            match_res = re.search(r'\d+', restarts)
            if match_res:
                restart_num = int(match_res.group(0))

            pods.append({
                "namespace": namespace,
                "name": name,
                "ready": ready,
                "status": status,
                "status_reason": status,
                "restarts": restart_num,
                "restarts_raw": restarts,
                "age": age,
                "ip": ip,
                "node": node,
                "severity": severity,
                "is_healthy": is_healthy
            })
        return pods

    def parse_services_table(self, raw_text: str) -> List[Dict[str, Any]]:
        """Parses `kubectl get svc -A` or `kubectl get svc -o wide` table."""
        lines = [line.strip() for line in raw_text.strip().splitlines() if line.strip()]
        if not lines:
            return []

        header_idx = -1
        has_namespace = False
        for i, line in enumerate(lines):
            if "NAME" in line and "TYPE" in line and "CLUSTER-IP" in line:
                header_idx = i
                has_namespace = "NAMESPACE" in line
                break

        if header_idx == -1:
            return []

        services = []
        for line in lines[header_idx + 1:]:
            if line.startswith("$") or line.startswith(">") or ("NAME" in line and "ENDPOINTS" in line):
                break
            parts = re.split(r'\s{2,}|\t+', line)
            if len(parts) < (4 if has_namespace else 3):
                parts = line.split()
            if len(parts) < (4 if has_namespace else 3):
                continue

            idx = 0
            namespace = parts[idx] if has_namespace else "default"
            if has_namespace:
                idx += 1

            name = parts[idx]
            svc_type = parts[idx + 1] if len(parts) > idx + 1 else "ClusterIP"
            cluster_ip = parts[idx + 2] if len(parts) > idx + 2 else ""
            external_ip = parts[idx + 3] if len(parts) > idx + 3 else ""
            ports_str = parts[idx + 4] if len(parts) > idx + 4 else ""
            age = parts[idx + 5] if len(parts) > idx + 5 else ""
            selector_str = parts[idx + 6] if len(parts) > idx + 6 else ""

            # Parse selector if present
            selector = {}
            if selector_str and selector_str != "<none>":
                for pair in selector_str.split(","):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        selector[k.strip()] = v.strip()

            # Parse ports
            ports = []
            if ports_str and ports_str != "<none>":
                for p_item in ports_str.split(","):
                    p_match = re.search(r'(\d+)(?::(\d+))?/(TCP|UDP)', p_item)
                    if p_match:
                        p_port = int(p_match.group(1))
                        ports.append({"port": p_port, "targetPort": p_port, "protocol": p_match.group(3)})

            services.append({
                "namespace": namespace,
                "name": name,
                "type": svc_type,
                "cluster_ip": cluster_ip,
                "external_ip": external_ip,
                "ports": ports,
                "age": age,
                "selector": selector,
                "endpoints": []
            })
        return services

    def parse_endpoints_table(self, raw_text: str) -> List[Dict[str, Any]]:
        """Parses `kubectl get ep -A` or `kubectl get endpoints` table."""
        lines = [line.strip() for line in raw_text.strip().splitlines() if line.strip()]
        if not lines:
            return []

        header_idx = -1
        has_namespace = False
        for i, line in enumerate(lines):
            if "NAME" in line and "ENDPOINTS" in line:
                header_idx = i
                has_namespace = "NAMESPACE" in line
                break

        if header_idx == -1:
            return []

        endpoints = []
        for line in lines[header_idx + 1:]:
            if line.startswith("$") or line.startswith(">") or ("LAST SEEN" in line and "TYPE" in line):
                break
            parts = re.split(r'\s{2,}|\t+', line)
            if len(parts) < (2 if has_namespace else 1):
                parts = line.split()
            if len(parts) < (2 if has_namespace else 1):
                continue

            idx = 0
            namespace = parts[idx] if has_namespace else "default"
            if has_namespace:
                idx += 1

            name = parts[idx]
            ep_str = parts[idx + 1] if len(parts) > idx + 1 else ""
            age = parts[idx + 2] if len(parts) > idx + 2 else ""

            ep_list = []
            if ep_str and ep_str != "<none>":
                ep_list = [ep.strip() for ep in ep_str.split(",") if ep.strip()]

            endpoints.append({
                "namespace": namespace,
                "name": name,
                "endpoints": ep_list,
                "age": age
            })
        return endpoints

    def parse_events_table(self, raw_text: str) -> List[Dict[str, Any]]:
        """Parses `kubectl get events -A` or `kubectl get events` table."""
        lines = [line.strip() for line in raw_text.strip().splitlines() if line.strip()]
        if not lines:
            return []

        header_idx = -1
        has_namespace = False
        for i, line in enumerate(lines):
            if ("TYPE" in line and "REASON" in line and "OBJECT" in line) or ("LAST SEEN" in line and "REASON" in line):
                header_idx = i
                has_namespace = "NAMESPACE" in line
                break

        if header_idx == -1:
            return []

        events = []
        for line in lines[header_idx + 1:]:
            if line.startswith("$") or line.startswith(">"):
                break
            parts = re.split(r'\s{2,}|\t+', line)
            if len(parts) < 4:
                continue

            idx = 0
            namespace = parts[idx] if has_namespace else "default"
            if has_namespace:
                idx += 1

            last_seen = parts[idx] if len(parts) > idx else ""
            ev_type = parts[idx + 1] if len(parts) > idx + 1 else "Normal"
            reason = parts[idx + 2] if len(parts) > idx + 2 else ""
            obj = parts[idx + 3] if len(parts) > idx + 3 else ""
            msg = " ".join(parts[idx + 4:]) if len(parts) > idx + 4 else ""

            events.append({
                "namespace": namespace,
                "last_seen": last_seen,
                "type": ev_type,
                "reason": reason,
                "object": obj,
                "message": msg
            })
        return events

    def _evaluate_pod_severity(self, status: str, ready: str = "") -> str:
        critical_statuses = {
            "CrashLoopBackOff", "OOMKilled", "Error", "Evicted", "NodeLost",
            "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError"
        }
        if any(cs.lower() in status.lower() for cs in critical_statuses):
            return "CRITICAL"
        if status.startswith("Init:") and ("error" in status.lower() or "crash" in status.lower()):
            return "CRITICAL"
        if status in {"Pending", "Terminating", "ContainerCreating"} or status.startswith("Init:"):
            return "WARNING"
        if status in {"Running", "Completed"}:
            if ready and "/" in ready:
                try:
                    c_ready, c_total = ready.split("/")
                    if int(c_ready) < int(c_total) and status == "Running":
                        return "WARNING"
                except Exception:
                    pass
            return "NORMAL"
        return "WARNING"

    def _parse_text_cli_dump(self, text: str) -> Dict[str, Any]:
        """Auto-slices multi-command CLI pastes into a unified model."""
        model: Dict[str, Any] = {
            "version": "v1.26.0",
            "nodes": [],
            "pods": [],
            "services": [],
            "events": []
        }

        # Check for nodes table
        if re.search(r'\bNAME\s+STATUS\s+ROLES\b', text) or re.search(r'\bNAME\s+STATUS\s+AGE\s+VERSION\b', text):
            model["nodes"] = self.parse_nodes_table(text)
            if model["nodes"]:
                model["version"] = model["nodes"][0].get("version", "v1.26.0")

        # Check for pods table
        if re.search(r'\bNAME\s+READY\s+STATUS\b', text) or re.search(r'\bREADY\s+STATUS\s+RESTARTS\b', text):
            model["pods"] = self.parse_pods_table(text)

        # Check for services table
        if re.search(r'\bNAME\s+TYPE\s+CLUSTER-IP\b', text):
            model["services"] = self.parse_services_table(text)

        # Check for endpoints table
        if re.search(r'\bNAME\s+ENDPOINTS\b', text):
            endpoints = self.parse_endpoints_table(text)
            ep_map = {(ep["namespace"], ep["name"]): ep["endpoints"] for ep in endpoints}
            for svc in model["services"]:
                key = (svc.get("namespace", "default"), svc.get("name", ""))
                if key in ep_map:
                    svc["endpoints"] = ep_map[key]

        # Check for events table
        if re.search(r'\bREASON\s+OBJECT\b', text) or re.search(r'\bLAST SEEN\s+TYPE\b', text):
            model["events"] = self.parse_events_table(text)

        return model
