"""
KubeScope Automated Test Suite
Verifies:
1. Parser JSON and text ingestion.
2. Diagnostician detection for OOMKilled, CrashLoop, Service Selector Mismatch.
3. CVE Scanner accuracy.
4. Upgrade Advisor multi-hop calculations and deprecated API warnings.
"""
import unittest
import json
import os

from core.parser import KubeParser
from core.diagnostician import KubeDiagnostician
from core.cve_scanner import CVEScanner
from core.upgrade_advisor import UpgradeAdvisor

class TestKubeScopeEngine(unittest.TestCase):
    def setUp(self):
        self.parser = KubeParser()
        self.diagnostician = KubeDiagnostician()
        self.cve_scanner = CVEScanner()
        self.upgrade_advisor = UpgradeAdvisor()

        samples_dir = os.path.join(os.path.dirname(__file__), "samples")
        sample_path = os.path.join(samples_dir, "sample_cluster_issues.json")
        with open(sample_path, "r", encoding="utf-8") as f:
            self.sample_issues = json.load(f)

    def test_diagnosis_oom_and_crash(self):
        cluster_model = self.parser.parse_input(self.sample_issues)
        diag = self.diagnostician.diagnose_cluster(cluster_model)

        self.assertLess(diag["health_score"], 80)
        self.assertEqual(diag["stats"]["critical_pods"], 2)

        # Check OOM issue
        oom_issue = next((i for i in diag["issues"] if "OOMKilled" in i["title"]), None)
        self.assertIsNotNone(oom_issue)
        self.assertEqual(oom_issue["severity"], "CRITICAL")
        self.assertTrue(len(oom_issue["log_snippet"]) > 0)

        # Check Service Blackhole issue
        svc_issue = next((i for i in diag["issues"] if i["category"] == "NETWORK_BLACKHOLE"), None)
        self.assertIsNotNone(svc_issue)
        self.assertIn("web-portal-svc", svc_issue["target"])

    def test_cve_scanner(self):
        # Test v1.26.2 has CVEs
        res_26 = self.cve_scanner.scan_cluster_version("v1.26.2")
        self.assertTrue(res_26["total_cves"] > 0)
        cve_ids = [c["id"] for c in res_26["vulnerabilities"]]
        self.assertIn("CVE-2023-3676", cve_ids)

        # Test ancient v1.10 has critical CVE-2018-1002105
        res_ancient = self.cve_scanner.scan_cluster_version("v1.10.2")
        self.assertTrue(any(c["id"] == "CVE-2018-1002105" for c in res_ancient["vulnerabilities"]))

    def test_upgrade_advisor_multihop(self):
        # 1.24 to 1.27 requires multi-hop
        plan = self.upgrade_advisor.plan_upgrade("v1.24.2", "v1.27.0", "kubeadm")
        self.assertTrue(plan["success"])
        self.assertTrue(plan["need_multihop"])
        self.assertEqual(plan["hop_count"], 3)

        # Deprecation check: PSP removed in 25
        dep_apis = [d["api"] for d in plan["deprecations"]]
        self.assertTrue(any("PodSecurityPolicy" in a for a in dep_apis))

        # Check runbook contains etcd snapshot
        self.assertTrue(any("etcdctl" in step["command"] for step in plan["runbook"]))

    def test_log_analyzer(self):
        from core.log_analyzer import LogAnalyzer
        analyzer = LogAnalyzer()

        # Test OOM log
        oom_log = (
            "2026-10-19T02:15:30Z [WARN] Memory rising\n"
            "2026-10-19T02:15:32Z [ERROR] java.lang.OutOfMemoryError: Java heap space\n"
            "2026-10-19T02:15:33Z [SYSTEM] Container terminated with exit code 137 (SIGKILL)\n"
        )
        res_oom = analyzer.analyze_log(oom_log, "payment-pod", "prod")
        self.assertTrue(res_oom["success"])
        self.assertEqual(res_oom["matched_issues"][0]["id"], "OOM_HEAP")
        self.assertTrue(any("payment-pod" in c for c in res_oom["matched_issues"][0]["actionable_commands"]))

        # Test Database Timeout log
        db_log = "2026-10-19 [ERROR] dial tcp 10.96.200.12:6379: i/o timeout\npanic: failed db"
        res_db = analyzer.analyze_log(db_log, "auth-pod", "prod")
        self.assertTrue(res_db["success"])
        self.assertEqual(res_db["matched_issues"][0]["id"], "DB_CONN_TIMEOUT")

    def test_cli_table_parsing(self):
        raw_pods_cli = (
            "NAMESPACE     NAME                                      READY   STATUS             RESTARTS       AGE   IP            NODE\n"
            "production    payment-processor-7b98fd-xq9lm            0/1     CrashLoopBackOff   14 (2m ago)    2d    10.244.1.42   k8s-worker-01\n"
            "production    web-frontend-99fa4-8hh2n                  1/1     Running            0              5d    10.244.1.30   k8s-worker-01\n"
        )
        parsed = self.parser.parse_pods_table(raw_pods_cli)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0]["status"], "CrashLoopBackOff")
        self.assertEqual(parsed[0]["severity"], "CRITICAL")
        self.assertEqual(parsed[1]["status"], "Running")
        self.assertEqual(parsed[1]["severity"], "NORMAL")

    def test_route_tracer(self):
        from core.route_tracer import RouteTracer
        tracer = RouteTracer()
        samples_dir = os.path.join(os.path.dirname(__file__), "samples")
        sample_path = os.path.join(samples_dir, "sample_broken_routes.json")
        with open(sample_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        res = tracer.trace_traffic_route(data["ingresses"], data["services"], data["pods"])
        self.assertGreater(res["total_routes"], 0)
        self.assertGreater(res["broken_routes"], 0)
        
        # Verify selector mismatch route was caught
        broken_types = [r["broken_layer"] for r in res["routes"] if r["broken_layer"]]
        self.assertIn("SERVICE_TO_ENDPOINTS", broken_types)
        # Verify readiness failure route was caught
        self.assertIn("ENDPOINTS_UNREADY_PROBES", broken_types)

    def test_infra_doctor_certs(self):
        from core.infra_doctor import InfraDoctor
        doc = InfraDoctor()
        samples_dir = os.path.join(os.path.dirname(__file__), "samples")
        with open(os.path.join(samples_dir, "sample_kubeadm_certs.txt"), "r", encoding="utf-8") as f:
            text = f.read()

        res = doc.parse_kubeadm_certs(text)
        self.assertTrue(res["success"])
        self.assertGreater(res["summary"]["expired"], 0)
        self.assertGreater(res["summary"]["warning"], 0)
        
        # Must have renewal commands
        rec = res["recommendations"][0]
        self.assertTrue(any("kubeadm certs renew" in c for c in rec["commands"]))

    def test_infra_doctor_readyz(self):
        from core.infra_doctor import InfraDoctor
        doc = InfraDoctor()
        samples_dir = os.path.join(os.path.dirname(__file__), "samples")
        with open(os.path.join(samples_dir, "sample_readyz.txt"), "r", encoding="utf-8") as f:
            text = f.read()

        res = doc.parse_readyz_output(text)
        self.assertTrue(res["success"])
        self.assertEqual(res["overall_status"], "UNHEALTHY")
        self.assertGreater(res["failed_count"], 0)
        
        # etcd analysis must be generated
        etcd_item = next((a for a in res["analysis"] if "etcd" in a["component"].lower()), None)
        self.assertIsNotNone(etcd_item)

    def test_deep_pod_diagnostics(self):
        pod_init = {
            "name": "db-migration-pod",
            "namespace": "prod",
            "status_reason": "Init:CrashLoopBackOff",
            "restarts": 4,
            "limits": {"cpu": "100m", "memory": "128Mi"}
        }
        pod_evicted = {
            "name": "worker-heavy-pod",
            "namespace": "prod",
            "status_reason": "Evicted",
            "restarts": 0,
            "limits": {"cpu": "100m", "memory": "128Mi"}
        }
        issues_init = self.diagnostician._diagnose_single_pod(pod_init, {})
        self.assertTrue(any(i["category"] == "INIT_CONTAINER_BLOCKED" for i in issues_init))

        issues_evicted = self.diagnostician._diagnose_single_pod(pod_evicted, {})
        self.assertTrue(any(i["category"] == "EVICTED_POD" for i in issues_evicted))

    def test_supply_chain_auditor(self):
        from core.supply_chain import SupplyChainAuditor
        auditor = SupplyChainAuditor()
        
        sample_req = (
            "requests>=2.25.0\n"
            "reqeusts==2.28.1\n"
            "urllib3==1.26.15 --hash=sha256:abcd1234ef567890\n"
        )
        res = auditor.audit_requirements(sample_req)
        self.assertTrue(res["success"])
        self.assertEqual(res["packages_count"], 3)
        self.assertEqual(res["hashed_count"], 1)
        
        # Verify typosquatting was caught
        typo_finding = next((f for f in res["findings"] if f["category"] == "TYPOSQUATTING"), None)
        self.assertIsNotNone(typo_finding)
        self.assertEqual(typo_finding["target"], "reqeusts")

        # Verify floating version was caught
        float_finding = next((f for f in res["findings"] if f["category"] == "FLOATING_VERSION"), None)
        self.assertIsNotNone(float_finding)

        # Test container images audit
        pods = [{
            "name": "payment-api",
            "namespace": "prod",
            "images": ["nginx:latest", "corp.harbor/api:v1.0@sha256:123456"],
            "security_context": {"runAsNonRoot": False, "readOnlyRootFilesystem": False}
        }]
        res_container = auditor.audit_container_images(pods)
        self.assertTrue(any(f["category"] == "MUTABLE_TAG" for f in res_container["findings"]))
        self.assertTrue(any(f["category"] == "RUNTIME_ESCALATION_RISK" for f in res_container["findings"]))

if __name__ == '__main__':
    unittest.main()
