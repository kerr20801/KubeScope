"""
KubeScope - YAML Studio & Automatic Remediation Patch Generator
Provides 1-click YAML generation, diff preview, and copy-pasteable kubectl CLI commands for:
1. Namespace creation with Pod Security Standards (PSS) & ResourceQuota / LimitRange.
2. Pod/Deployment OOM resource patches (bump limits/requests).
3. Service selector blackhole fixes.
4. Liveness & Readiness health probe configurations.
"""
from typing import Any, Dict, Optional

class YAMLWorkbench:
    def __init__(self):
        pass

    def generate_namespace(
        self,
        name: str,
        pss_level: str = "baseline",
        cpu_quota: Optional[str] = "4",
        mem_quota: Optional[str] = "8Gi"
    ) -> Dict[str, Any]:
        """
        Generates a production-ready Namespace YAML with Pod Security Standards
        and optional ResourceQuota / LimitRange to prevent noisy-neighbor cluster crashes.
        """
        ns_clean = name.strip().lower() or "custom-namespace"
        pss = pss_level.lower() if pss_level.lower() in ("privileged", "baseline", "restricted") else "baseline"

        yaml_lines = [
            "apiVersion: v1",
            "kind: Namespace",
            "metadata:",
            f"  name: {ns_clean}",
            "  labels:",
            f"    pod-security.kubernetes.io/enforce: {pss}",
            f"    pod-security.kubernetes.io/audit: {pss}",
            f"    pod-security.kubernetes.io/warn: {pss}",
            f"    app.kubernetes.io/managed-by: kubescope"
        ]

        if cpu_quota or mem_quota:
            yaml_lines.extend([
                "---",
                "apiVersion: v1",
                "kind: ResourceQuota",
                "metadata:",
                f"  name: {ns_clean}-quota",
                f"  namespace: {ns_clean}",
                "spec:",
                "  hard:"
            ])
            if cpu_quota:
                yaml_lines.append(f"    requests.cpu: \"{cpu_quota}\"")
                yaml_lines.append(f"    limits.cpu: \"{int(float(cpu_quota) * 2)}\"")
            if mem_quota:
                yaml_lines.append(f"    requests.memory: {mem_quota}")
                yaml_lines.append(f"    limits.memory: {mem_quota}")

            # Also add LimitRange default container constraints
            yaml_lines.extend([
                "---",
                "apiVersion: v1",
                "kind: LimitRange",
                "metadata:",
                f"  name: {ns_clean}-defaults",
                f"  namespace: {ns_clean}",
                "spec:",
                "  limits:",
                "  - default:",
                "      cpu: 500m",
                "      memory: 512Mi",
                "    defaultRequest:",
                "      cpu: 100m",
                "      memory: 128Mi",
                "    type: Container"
            ])

        full_yaml = "\n".join(yaml_lines)
        cli_command = f"cat <<EOF | kubectl apply -f -\n{full_yaml}\nEOF"

        return {
            "success": True,
            "type": "namespace",
            "namespace": ns_clean,
            "pss_level": pss,
            "yaml": full_yaml,
            "kubectl_command": cli_command,
            "explanation": f"已建立安全加固之命名空間 `{ns_clean}`，強制套用 PSS `{pss}` 規範並配置資源額度配額防範鄰居干擾。"
        }

    def generate_resource_patch(
        self,
        deployment_name: str,
        namespace: str = "default",
        mem_limit: str = "1Gi",
        mem_request: str = "512Mi",
        cpu_limit: str = "1000m",
        cpu_request: str = "250m"
    ) -> Dict[str, Any]:
        """
        Generates remediation YAML & kubectl patch command for OOMKilled containers.
        """
        dep_clean = deployment_name.strip() or "payment-processor"
        ns_clean = namespace.strip() or "default"

        patch_yaml = f"""apiVersion: apps/v1
kind: Deployment
metadata:
  name: {dep_clean}
  namespace: {ns_clean}
spec:
  template:
    spec:
      containers:
      - name: {dep_clean}
        resources:
          limits:
            cpu: "{cpu_limit}"
            memory: "{mem_limit}"
          requests:
            cpu: "{cpu_request}"
            memory: "{mem_request}"
"""

        cli_command = (
            f"kubectl patch deployment {dep_clean} -n {ns_clean} --type=merge -p '"
            f"{{\"spec\":{{\"template\":{{\"spec\":{{\"containers\":[{{\"name\":\"{dep_clean}\","
            f"\"resources\":{{\"limits\":{{\"cpu\":\"{cpu_limit}\",\"memory\":\"{mem_limit}\"}},"
            f"\"requests\":{{\"cpu\":\"{cpu_request}\",\"memory\":\"{mem_request}\"}}}}}}]}}}}}}}}'"
        )

        return {
            "success": True,
            "type": "resource_patch",
            "deployment": dep_clean,
            "namespace": ns_clean,
            "yaml": patch_yaml.strip(),
            "kubectl_command": cli_command,
            "kubectl_apply_command": f"cat <<EOF | kubectl apply -f -\n{patch_yaml.strip()}\nEOF",
            "explanation": f"將 {ns_clean}/{dep_clean} 的記憶體上限由原先配額調高至 {mem_limit} (Requests: {mem_request})，直接止血 OOM 137 崩潰。"
        }

    def generate_service_fix(
        self,
        service_name: str,
        namespace: str = "default",
        correct_selector_app: str = "web-frontend",
        service_port: int = 80,
        target_port: int = 8080
    ) -> Dict[str, Any]:
        """
        Generates fixed Service YAML when selectors are mismatched or endpoints are empty.
        """
        svc_clean = service_name.strip() or "web-portal-svc"
        ns_clean = namespace.strip() or "default"
        app_label = correct_selector_app.strip() or "web-frontend"

        fixed_yaml = f"""apiVersion: v1
kind: Service
metadata:
  name: {svc_clean}
  namespace: {ns_clean}
spec:
  type: ClusterIP
  selector:
    app: {app_label}
  ports:
  - name: http
    port: {service_port}
    targetPort: {target_port}
    protocol: TCP
"""
        cli_command = f"cat <<EOF | kubectl apply -f -\n{fixed_yaml.strip()}\nEOF"

        return {
            "success": True,
            "type": "service_fix",
            "service": svc_clean,
            "namespace": ns_clean,
            "yaml": fixed_yaml.strip(),
            "kubectl_command": cli_command,
            "explanation": f"重新校準 Service 選擇器 `app: {app_label}`，使流量正確導引至後端就緒 Pods，解除 503 服務黑洞。"
        }

    def generate_probe_fix(
        self,
        container_name: str = "app",
        port: int = 8080,
        path: str = "/healthz",
        initial_delay: int = 15,
        period: int = 10,
        timeout: int = 3
    ) -> Dict[str, Any]:
        """
        Generates Liveness and Readiness Probe YAML snippet.
        """
        probe_yaml = f"""livenessProbe:
  httpGet:
    path: {path}
    port: {port}
  initialDelaySeconds: {initial_delay}
  periodSeconds: {period}
  timeoutSeconds: {timeout}
  failureThreshold: 3
readinessProbe:
  httpGet:
    path: {path}
    port: {port}
  initialDelaySeconds: {max(5, initial_delay - 5)}
  periodSeconds: {period}
  timeoutSeconds: {timeout}
  failureThreshold: 2
"""
        return {
            "success": True,
            "type": "probe_fix",
            "yaml": probe_yaml.strip(),
            "explanation": f"配置合理之健康探針：預留 {initial_delay} 秒初始延遲防範 Java/Node 啟動慢遭誤殺，就緒探針及早納入 Endpoints 流量分發。"
        }
