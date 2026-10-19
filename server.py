"""
KubeScope - Zero-Dependency Local Web Server & API Gateway
Port: 8930
Provides RESTful APIs for:
1. Kubernetes cluster diagnosis, Pod crash forensic & Service blackhole detection.
2. CVE vulnerability scanning for K8s versions and components.
3. Step-by-step upgrade advisor & deprecated API audit.
4. Local Ollama LLM copilot & offline SRE expert gateway.
"""
import sys
import os
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver
import subprocess
from typing import Any

# Ensure stdout handles UTF-8 on Windows cp950
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

from core.parser import KubeParser
from core.diagnostician import KubeDiagnostician
from core.cve_scanner import CVEScanner
from core.upgrade_advisor import UpgradeAdvisor
from core.llm_gateway import LLMGateway
from core.log_analyzer import LogAnalyzer
from core.infra_doctor import InfraDoctor
from core.route_tracer import RouteTracer
from core.supply_chain import SupplyChainAuditor

PORT = 8930
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")

parser = KubeParser()
diagnostician = KubeDiagnostician()
cve_scanner = CVEScanner()
upgrade_advisor = UpgradeAdvisor()
llm_gateway = LLMGateway()
log_analyzer = LogAnalyzer()
infra_doctor = InfraDoctor()
route_tracer = RouteTracer()
supply_chain_auditor = SupplyChainAuditor()

class KubeScopeHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def _send_json(self, data: Any, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path in ("/", "/index.html"):
            index_path = os.path.join(WEB_DIR, "index.html")
            if os.path.exists(index_path):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                with open(index_path, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.send_error(404, "index.html not found")

        elif path == "/api/status":
            import shutil
            ollama_status = llm_gateway.check_ollama()
            kubectl_found = shutil.which("kubectl") is not None

            self._send_json({
                "status": "online",
                "version": "1.0.0",
                "kubectl_installed": kubectl_found,
                "ollama": ollama_status
            })

        elif path == "/api/sample":
            query_params = urllib.parse.parse_qs(parsed_url.query)
            sample_type = query_params.get("type", ["issues"])[0]
            filename_map = {
                "issues": "sample_cluster_issues.json",
                "healthy": "sample_healthy_cluster.json",
                "legacy": "sample_cve_legacy.json"
            }
            fname = filename_map.get(sample_type, "sample_cluster_issues.json")
            target_path = os.path.join(SAMPLES_DIR, fname)
            if os.path.exists(target_path):
                with open(target_path, "r", encoding="utf-8") as f:
                    self._send_json(json.load(f))
            else:
                self._send_json({"error": "Sample file not found"}, 404)

        elif path == "/api/sample-route":
            target_path = os.path.join(SAMPLES_DIR, "sample_broken_routes.json")
            if os.path.exists(target_path):
                with open(target_path, "r", encoding="utf-8") as f:
                    self._send_json(json.load(f))
            else:
                self._send_json({"error": "sample_broken_routes.json not found"}, 404)

        elif path == "/api/sample-cert":
            target_path = os.path.join(SAMPLES_DIR, "sample_kubeadm_certs.txt")
            if os.path.exists(target_path):
                with open(target_path, "r", encoding="utf-8") as f:
                    self._send_json({"text": f.read()})
            else:
                self._send_json({"error": "sample_kubeadm_certs.txt not found"}, 404)

        elif path == "/api/sample-readyz":
            target_path = os.path.join(SAMPLES_DIR, "sample_readyz.txt")
            if os.path.exists(target_path):
                with open(target_path, "r", encoding="utf-8") as f:
                    self._send_json({"text": f.read()})
            else:
                self._send_json({"error": "sample_readyz.txt not found"}, 404)

        elif path == "/api/sample-requirements":
            target_path = os.path.join(SAMPLES_DIR, "sample_vulnerable_requirements.txt")
            if os.path.exists(target_path):
                with open(target_path, "r", encoding="utf-8") as f:
                    self._send_json({"text": f.read()})
            else:
                self._send_json({"error": "sample_vulnerable_requirements.txt not found"}, 404)

        else:
            self.send_error(404, "Endpoint not found")

    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')

        try:
            body = json.loads(post_data) if post_data.strip().startswith("{") else {"raw_text": post_data}
        except Exception:
            body = {"raw_text": post_data}

        if path == "/api/diagnose":
            # Can receive structured JSON or raw text CLI dumps
            raw_input = body.get("data", body.get("raw_text", body))
            cluster_model = parser.parse_input(raw_input)
            diag_result = diagnostician.diagnose_cluster(cluster_model)

            # Auto-run CVE scan on detected version
            version_str = cluster_model.get("version", "v1.26.0")
            cve_result = cve_scanner.scan_cluster_version(version_str)

            self._send_json({
                "success": True,
                "version": version_str,
                "cluster_model": cluster_model,
                "diagnosis": diag_result,
                "cve_summary": cve_result
            })

        elif path == "/api/cve-scan":
            ver = body.get("version", "v1.26.0")
            res = cve_scanner.scan_cluster_version(ver)
            self._send_json(res)

        elif path == "/api/upgrade-plan":
            curr = body.get("current_version", "v1.24.2")
            targ = body.get("target_version", "v1.26.15")
            toolchain = body.get("toolchain", "kubeadm")
            plan = upgrade_advisor.plan_upgrade(curr, targ, toolchain)
            self._send_json(plan)

        elif path == "/api/parse-nodes":
            raw_text = body.get("text", "")
            nodes = parser.parse_nodes_table(raw_text)
            self._send_json({"nodes": nodes, "total": len(nodes)})

        elif path == "/api/parse-pods":
            raw_text = body.get("text", "")
            pods = parser.parse_pods_table(raw_text)
            unhealthy_count = sum(1 for p in pods if not p.get("is_healthy"))
            self._send_json({
                "pods": pods,
                "total": len(pods),
                "unhealthy_count": unhealthy_count
            })

        elif path == "/api/analyze-log":
            log_text = body.get("log", "")
            pod_name = body.get("pod_name", "")
            namespace = body.get("namespace", "")
            result = log_analyzer.analyze_log(log_text, pod_name, namespace)
            self._send_json(result)

        elif path == "/api/chat":
            query = body.get("query", "")
            context = body.get("context", None)
            model = body.get("model", "qwen3.5:latest")
            provider = body.get("provider", "auto")
            api_url = body.get("api_url", "")
            api_key = body.get("api_key", "")
            answer = llm_gateway.ask(query, context, model, provider, api_url, api_key)
            self._send_json(answer)

        elif path == "/api/trace-route":
            # Supports direct JSON or wrapper
            data = body.get("data", body)
            ingresses = data.get("ingresses", [])
            services = data.get("services", [])
            pods = data.get("pods", [])
            res = route_tracer.trace_traffic_route(ingresses, services, pods)
            self._send_json(res)

        elif path == "/api/check-certs":
            raw_text = body.get("text", body.get("raw_text", ""))
            res = infra_doctor.parse_kubeadm_certs(raw_text)
            self._send_json(res)

        elif path == "/api/check-kubeapi":
            raw_text = body.get("text", body.get("raw_text", ""))
            res = infra_doctor.parse_readyz_output(raw_text)
            self._send_json(res)

        elif path == "/api/audit-network":
            nodes = body.get("nodes", [])
            pods = body.get("pods", [])
            res = infra_doctor.audit_network_architecture(nodes, pods)
            self._send_json(res)

        elif path == "/api/audit-supply-chain":
            raw_text = body.get("text", body.get("raw_text", ""))
            res = supply_chain_auditor.audit_requirements(raw_text)
            self._send_json(res)

        elif path == "/api/audit-container-supply-chain":
            pods = body.get("pods", [])
            res = supply_chain_auditor.audit_container_images(pods)
            self._send_json(res)

        else:
            self.send_error(404, "Endpoint not found")

class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

def _open_browser_delayed():
    import time
    import webbrowser
    time.sleep(0.6)
    try:
        webbrowser.open(f"http://localhost:{PORT}/")
    except Exception:
        pass

def run():
    import threading
    server_address = ('', PORT)

    # Automatically open browser across all OS (Windows, macOS, Linux) unless --no-browser is passed
    if "--no-browser" not in sys.argv:
        threading.Thread(target=_open_browser_delayed, daemon=True).start()

    with ReusableTCPServer(server_address, KubeScopeHandler) as httpd:
        print(f"=======================================================")
        print(f"  [*] KubeScope - Kubernetes 異常透視與白話排障軍師")
        print(f"  跨平台相容: macOS | Linux | Windows (純標準庫 0 依賴)")
        print(f"  Web Dashboard: http://localhost:{PORT}/")
        print(f"  API Gateway  : http://localhost:{PORT}/api/status")
        print(f"=======================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n關閉 KubeScope 服務...")

if __name__ == '__main__':
    run()
