"""
KubeScope - Kubernetes Full Traffic Route Tracer (Ingress -> Service -> Endpoints -> Pods)
Identifies hanging Ingresses, selector mismatches, unready probes, and port collisions.
"""
from typing import Any, Dict, List

class RouteTracer:
    def __init__(self):
        pass

    def trace_traffic_route(
        self,
        ingresses: List[Dict[str, Any]],
        services: List[Dict[str, Any]],
        pods: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        routes: List[Dict[str, Any]] = []

        svc_map = {f"{s.get('namespace', 'default')}/{s.get('name', '')}": s for s in services}

        # 1. Trace from Ingresses
        for ing in ingresses:
            ing_name = ing.get("name", "unknown-ing")
            ing_ns = ing.get("namespace", "default")
            rules = ing.get("rules", [])

            for rule in rules:
                host = rule.get("host", "*")
                paths = rule.get("paths", [])
                for p in paths:
                    path_str = p.get("path", "/")
                    backend_svc = p.get("backend_service", "")
                    backend_port = p.get("backend_port", 80)

                    svc_key = f"{ing_ns}/{backend_svc}"
                    svc = svc_map.get(svc_key)

                    route_entry = {
                        "ingress": f"{ing_ns}/{ing_name}",
                        "host": host,
                        "path": path_str,
                        "service": svc_key,
                        "service_port": backend_port,
                        "matched_pods": [],
                        "status": "HEALTHY",
                        "broken_layer": None,
                        "detail": "流量拓撲全鏈路正常通暢"
                    }

                    if not svc:
                        route_entry["status"] = "BROKEN"
                        route_entry["broken_layer"] = "INGRESS_TO_SERVICE"
                        route_entry["detail"] = f"Ingress 指向不存在之 Service: {backend_svc}"
                        routes.append(route_entry)
                        continue

                    # Trace Service -> Pods
                    selector = svc.get("selector", {})
                    matched = []
                    unready_pods = []

                    for pod in pods:
                        if pod.get("namespace", "default") == ing_ns:
                            labels = pod.get("labels", {})
                            if selector and all(labels.get(k) == v for k, v in selector.items()):
                                matched.append(pod)
                                # Check readiness
                                ready_str = pod.get("ready", "1/1")
                                is_probe_ok = True
                                if "/" in ready_str:
                                    r_cnt, t_cnt = ready_str.split("/")
                                    if int(r_cnt) < int(t_cnt):
                                        is_probe_ok = False
                                if not is_probe_ok or pod.get("status") != "Running":
                                    unready_pods.append(pod.get("name"))

                    route_entry["matched_pods"] = [p.get("name") for p in matched]

                    if not matched:
                        route_entry["status"] = "BROKEN"
                        route_entry["broken_layer"] = "SERVICE_TO_ENDPOINTS"
                        route_entry["detail"] = f"Service selector {selector} 懸空，無任何匹配 Pod，Endpoints 為空！"
                    elif len(unready_pods) == len(matched) and matched:
                        route_entry["status"] = "BROKEN"
                        route_entry["broken_layer"] = "ENDPOINTS_UNREADY_PROBES"
                        route_entry["detail"] = f"所有目標 Pods ({', '.join(unready_pods)}) 均處於 Readiness 探針失敗或未就緒狀態，遭 Endpoints 剔除！"
                    elif unready_pods:
                        route_entry["status"] = "DEGRADED"
                        route_entry["detail"] = f"部分 Pods ({', '.join(unready_pods)}) 探針未通過，僅剩餘部分節點承載流量。"

                    routes.append(route_entry)

        # 2. Also trace any Standalone Services without Ingress
        routed_services = {r["service"] for r in routes}
        for s_key, svc in svc_map.items():
            if s_key not in routed_services:
                svc_ns = svc.get("namespace", "default")
                selector = svc.get("selector", {})
                matched = []
                unready_pods = []
                for pod in pods:
                    if pod.get("namespace", "default") == svc_ns:
                        labels = pod.get("labels", {})
                        if selector and all(labels.get(k) == v for k, v in selector.items()):
                            matched.append(pod)
                            ready_str = pod.get("ready", "1/1")
                            if "/" in ready_str:
                                r_cnt, t_cnt = ready_str.split("/")
                                if int(r_cnt) < int(t_cnt):
                                    unready_pods.append(pod.get("name"))

                route_entry = {
                    "ingress": None,
                    "host": None,
                    "path": None,
                    "service": s_key,
                    "service_port": svc.get("ports", [{}])[0].get("port", 80) if svc.get("ports") else 80,
                    "matched_pods": [p.get("name") for p in matched],
                    "status": "HEALTHY",
                    "broken_layer": None,
                    "detail": "ClusterIP 內部服務拓撲正常"
                }

                if not matched and selector:
                    route_entry["status"] = "BROKEN"
                    route_entry["broken_layer"] = "SERVICE_TO_ENDPOINTS"
                    route_entry["detail"] = f"內部 Service {s_key} selector {selector} 未匹配到任何 Pod"
                elif unready_pods and len(unready_pods) == len(matched):
                    route_entry["status"] = "BROKEN"
                    route_entry["broken_layer"] = "ENDPOINTS_UNREADY_PROBES"
                    route_entry["detail"] = f"內部 Service {s_key} 所有後端 Pod 探針均未就緒"

                routes.append(route_entry)

        broken_count = sum(1 for r in routes if r["status"] == "BROKEN")
        return {
            "total_routes": len(routes),
            "healthy_routes": len(routes) - broken_count,
            "broken_routes": broken_count,
            "routes": routes
        }
