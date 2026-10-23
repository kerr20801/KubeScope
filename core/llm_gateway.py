"""
KubeScope - Local SRE AI Copilot & Offline Expert Gateway
Integrates local Ollama models (Qwen 3.5 / Qwen 2.5) with multi-turn continuous memory,
and provides zero-cloud fallback to deterministic SRE rule engine.
"""
import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

class LLMGateway:
    def __init__(self, ollama_url: str = "http://localhost:11434"):
        self.ollama_url = ollama_url
        self.default_model = "qwen3.5:latest"

    def check_ollama(self) -> Dict[str, Any]:
        """Checks if local Ollama daemon is reachable and lists downloaded models."""
        try:
            req = urllib.request.Request(f"{self.ollama_url}/api/tags", headers={"User-Agent": "KubeScope"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    models = [m.get("name") for m in data.get("models", [])]
                    # Select best default model
                    chosen_model = self.default_model
                    for candidate in ["qwen3.5:latest", "qwen3.5:4b", "qwen3.5:2b", "qwen2.5:1.5b", "qwen2.5-coder:1.5b"]:
                        if any(candidate in m for m in models):
                            chosen_model = next(m for m in models if candidate in m)
                            break
                    else:
                        if models:
                            chosen_model = models[0]

                    return {
                        "online": True,
                        "models": models,
                        "default_model": chosen_model
                    }
        except Exception:
            pass

        return {
            "online": False,
            "models": [],
            "default_model": "SRE 離線專家決策庫"
        }

    def ask(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
        model: str = "qwen3.5:latest",
        provider: str = "auto",
        api_url: str = "",
        api_key: str = "",
        messages: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Processes multi-turn questions or single prompts with K8s context.
        Falls back seamlessly to local deterministic SRE rule engine if Ollama is offline.
        """
        ollama_status = self.check_ollama()

        # Build System Prompt with CCIE/SRE Persona & Telemetry
        system_prompt = self._build_sre_system_prompt(context)

        if ollama_status["online"] and provider != "rule_fallback":
            try:
                actual_model = model if model in ollama_status["models"] else ollama_status["default_model"]
                answer = self._call_ollama_chat(system_prompt, query, actual_model, messages)
                if answer:
                    return {
                        "source": "ollama",
                        "model": actual_model,
                        "response": answer
                    }
            except Exception:
                pass

        # Fallback: Deterministic SRE Expert Rule Engine
        fallback_answer = self._offline_sre_expert_triage(query, context)
        return {
            "source": "rule_fallback",
            "model": "KubeScope 離線 SRE 專家決策庫",
            "response": fallback_answer
        }

    def _build_sre_system_prompt(self, context: Optional[Dict[str, Any]]) -> str:
        prompt = (
            "你是一位頂級資深 Kubernetes SRE 架構師與 Linux 系統排障專家 (Copilot)。\n"
            "請恪守以下三大實戰原則：\n"
            "1. 【強制全篇繁體中文】：嚴禁英文開頭或簡體字，一律採用台灣慣用專業詞彙（命名空間、容器、節點、服務、探針、日誌、選擇器）。\n"
            "2. 【切中要害、零教科書廢話】：嚴禁科普名詞理論（例如嚴禁開頭講「Kubernetes 是開源容器編排系統...」等廢話）！直接指出故障根因！\n"
            "3. 【直給可執行的 kubectl CLI 指令】：在 ```bash 程式碼區塊中提供現場維運人員可以直接複製執行的診斷與安全修復指令！\n\n"
        )
        if context:
            prompt += "【當前叢集診斷遙測快照】：\n"
            health = context.get("health_score", 100)
            prompt += f"- 叢集健康度：{health} / 100\n"
            stats = context.get("stats", {})
            prompt += f"- 統計：Pod 總數 {stats.get('total_pods', 0)} (異常: {stats.get('critical_pods', 0)})，節點: {stats.get('total_nodes', 0)}\n"
            issues = context.get("issues", [])
            if issues:
                prompt += "- 核心阻斷故障清單：\n"
                for idx, iss in enumerate(issues[:5], 1):
                    prompt += f"  {idx}. [{iss.get('severity')}] {iss.get('title')} (目標: {iss.get('target')})\n"
                    prompt += f"     原因: {iss.get('cause')}\n"
            prompt += "\n請根據上述遙測事實，切中要害回答維運人員的問題。\n"
        return prompt

    def _call_ollama_chat(
        self,
        system_prompt: str,
        user_query: str,
        model: str,
        messages: Optional[List[Dict[str, str]]] = None
    ) -> str:
        payload_messages: List[Dict[str, str]] = [{"role": "system", "content": system_prompt}]

        if messages and isinstance(messages, list):
            # Take last 8 messages (4 rounds of Q&A) for sliding memory
            for m in messages[-8:]:
                if m.get("role") in ("user", "assistant") and m.get("content"):
                    payload_messages.append({"role": m["role"], "content": m["content"]})
        else:
            payload_messages.append({"role": "user", "content": user_query})

        data = {
            "model": model,
            "messages": payload_messages,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "top_p": 0.9,
                "num_ctx": 4096
            }
        }

        req = urllib.request.Request(
            f"{self.ollama_url}/api/chat",
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=30.0) as resp:
            if resp.status == 200:
                result = json.loads(resp.read().decode("utf-8"))
                return result.get("message", {}).get("content", "").strip()
        return ""

    def _offline_sre_expert_triage(self, query: str, context: Optional[Dict[str, Any]]) -> str:
        """Deterministic SRE expert rule engine for air-gapped environments."""
        q_lower = query.lower()
        issues = context.get("issues", []) if context else []

        # 1. Ask about OOMKilled
        if "oom" in q_lower or "137" in q_lower or any("oom" in i.get("title", "").lower() for i in issues):
            oom_targets = [i.get("target") for i in issues if "oom" in i.get("title", "").lower()]
            target_str = oom_targets[0] if oom_targets else "<namespace>/<pod-name>"
            ns, pod = target_str.split("/") if "/" in target_str else ("default", target_str)
            return (
                f"### 🛡️ 【SRE 專家診斷：OOMKilled 記憶體溢位】\n\n"
                f"**根因判定**：容器進程申請之記憶體超出宣告之 `limits.memory` 門檻，遭 Linux cgroup OOM Killer 強制發送 SIGKILL (Exit Code 137) 擊殺。\n\n"
                f"**現場安全排查步驟**：\n"
                f"```bash\n"
                f"# 1. 檢視容器被擊殺之具體時間與最後宣告\n"
                f"kubectl describe pod -n {ns} {pod} | grep -E -A 5 -B 5 -i '(oom|last state|limits)'\n\n"
                f"# 2. 調閱死前最後日誌\n"
                f"kubectl logs -n {ns} {pod} --previous --tail=200\n\n"
                f"# 3. 建議調整資源配額 (範例：放寬至 512Mi 或 1Gi)\n"
                f"kubectl set resources deployment <deploy-name> -n {ns} --limits=memory=1Gi --requests=memory=512Mi\n"
                f"```\n"
            )

        # 2. Ask about CrashLoopBackOff
        if "crash" in q_lower or any("crash" in i.get("title", "").lower() for i in issues):
            crash_targets = [i.get("target") for i in issues if "crash" in i.get("title", "").lower()]
            target_str = crash_targets[0] if crash_targets else "<namespace>/<pod-name>"
            ns, pod = target_str.split("/") if "/" in target_str else ("default", target_str)
            return (
                f"### 🛡️ 【SRE 專家診斷：CrashLoopBackOff 應用啟動即崩潰】\n\n"
                f"**根因判定**：容器主進程一啟動便拋出錯誤退出，常見為：缺少環境變數/設定檔、連不上 DB/Redis、代碼 Panic 或權限不足。\n\n"
                f"**現場取證指令（關鍵在 --previous 死亡遺言）**：\n"
                f"```bash\n"
                f"# 1. 撈取上一代容器崩潰死亡前之關鍵錯誤堆疊 (90% 問題由此解答)\n"
                f"kubectl logs -n {ns} {pod} --previous --tail=200\n\n"
                f"# 2. 查看 Kubelet 排程事件 (是否存在 MountVolume.SetUp 失敗)\n"
                f"kubectl describe pod -n {ns} {pod} | grep -A 15 'Events:'\n\n"
                f"# 3. 若為環境變數缺失，檢查 ConfigMap/Secret 是否存在\n"
                f"kubectl get cm,secret -n {ns}\n"
                f"```\n"
            )

        # 3. Ask about Service / 502 / 503 / 路由黑洞
        if "503" in q_lower or "502" in q_lower or "service" in q_lower or "黑洞" in q_lower:
            return (
                "### 🛡️ 【SRE 專家診斷：Service 服務黑洞與 503 排查】\n\n"
                "**根因判定**：Service 的 `spec.selector` 與後端 Pod 宣告之 `metadata.labels` 不匹配，導致 EndpointSlice 為空，或 Pod 未通過就緒探針 (Readiness Probe)。\n\n"
                "**現場驗證與排查指令**：\n"
                "```bash\n"
                "# 1. 檢查 Service 背後之 Endpoints 是否為空\n"
                "kubectl get endpoints <service-name> -n <namespace>\n\n"
                "# 2. 比對 Service 選擇器與 Pod 實際標籤\n"
                "kubectl get svc <service-name> -n <namespace> -o jsonpath='{.spec.selector}'\n"
                "kubectl get pods -n <namespace> --show-labels\n\n"
                "# 3. 檢查 Pod 就緒探針狀態 (若為 0/1 則不會被掛載到 Endpoints)\n"
                "kubectl get pods -n <namespace> -l <app=selector-label>\n"
                "```\n"
            )

        # General cluster advice
        return (
            "### 🛡️ 【KubeScope SRE 專家會診總評】\n\n"
            "已為您全方位盤點當前集群遙測狀態。若要展開特定 Pod 取證，可點擊上方異常 Pod 卡片，複製對應之取證神鑰匙指令貼入終端機執行；若有具體日誌，可直接貼入「第 4 動：日誌深度法醫」進行秒級切片解析！\n"
        )
