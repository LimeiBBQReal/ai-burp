"""
AI-Burp IDE Mode CLI
专为 Kiro/Cursor 等 IDE 调用设计的命令行接口

用法:
    aiburp-ide prompt <project_id>                    # 获取恢复 Prompt
    aiburp-ide memory add <project_id> <type> <content>  # 添加记忆
    aiburp-ide memory search <project_id> <query>     # 搜索记忆
    aiburp-ide memory list <project_id>               # 列出记忆
    aiburp-ide finding add <project_id> <json>        # 添加发现
    aiburp-ide finding list <project_id>              # 列出发现
    aiburp-ide status <project_id>                    # 查看状态
    aiburp-ide tool probe <url> <param> <value>       # 探测参数
    aiburp-ide tool scan <url> <param> <value>        # 漏洞扫描

所有命令默认输出 JSON 格式，方便 IDE 解析。
"""

import argparse
import json
import sys
from typing import Any, Dict

from .orchestrator import SecurityOrchestrator
from .memory import MemoryManager


def json_output(data: Any, pretty: bool = False) -> str:
    """标准化 JSON 输出"""
    indent = 2 if pretty else None
    return json.dumps(data, ensure_ascii=False, indent=indent, default=str)


def success(data: Any = None, message: str = None) -> Dict:
    """成功响应"""
    result = {"ok": True}
    if message:
        result["message"] = message
    if data is not None:
        result["data"] = data
    return result


def error(message: str, code: str = "ERROR") -> Dict:
    """错误响应"""
    return {"ok": False, "error": code, "message": message}


# ============================================================
#                      Prompt 命令
# ============================================================

def cmd_prompt(args):
    """获取恢复 Prompt"""
    try:
        orch = SecurityOrchestrator(args.project_id)
        
        if args.type == "recovery":
            prompt = orch.generate_recovery_prompt()
        elif args.type == "researcher":
            prompt = orch.generate_researcher_prompt()
        elif args.type == "exhaustive":
            from .prompts import PromptTemplates
            # 穷举模式：注入当前上下文
            context = f"""
项目: {args.project_id}
目标: {orch.state.get('target', {}).get('goal', 'Security Audit')}
已发现: {len(orch.state.get('findings', []))} 个问题
已探索: {len(orch.state.get('exploration', {}).get('tried', []))} 条路径
"""
            prompt = PromptTemplates.EXHAUSTIVE_MODE.format(
                task_description=args.task or "继续安全审计",
                context=context
            )
        elif args.type == "hacker":
            from .prompts import PromptTemplates
            prompt = PromptTemplates.HACKER_MINDSET
        elif args.type == "chaos":
            from .prompts import PromptTemplates
            prompt = PromptTemplates.COMBINATORIAL_CHAOS
        elif args.type == "assumption":
            from .prompts import PromptTemplates
            prompt = PromptTemplates.ASSUMPTION_HUNTER
        elif args.type == "intuition":
            from .prompts import PromptTemplates
            prompt = PromptTemplates.INTUITION_COMBO
        elif args.type == "fuzz":
            from .prompts import PromptTemplates
            prompt = PromptTemplates.HYPER_RANDOM_FUZZ
        elif args.type == "cthulhu":
            from .prompts import PromptTemplates
            prompt = PromptTemplates.CTHULHU_CHAOS
        else:
            prompt = orch.generate_recovery_prompt()
        
        return success(data={"prompt": prompt, "type": args.type})
    except Exception as e:
        return error(str(e), "PROMPT_ERROR")


# ============================================================
#                      Memory 命令
# ============================================================

def cmd_memory_add(args):
    """添加记忆"""
    try:
        mem = MemoryManager(args.project_id)
        
        if args.type == "code":
            mem_id = mem.add_code(
                content=args.content,
                file=args.file or "unknown",
                line=args.line or 0
            )
        elif args.type == "finding":
            mem_id = mem.add_finding(
                content=args.content,
                severity=args.severity or "info",
                file=args.file or "",
                line=args.line or 0
            )
        elif args.type == "exploration":
            mem_id = mem.add_exploration(
                path=args.content,
                result=args.result or "unknown",
                reason=args.reason or ""
            )
        elif args.type == "instruction":
            mem_id = mem.add_instruction(
                content=args.content,
                priority=args.priority or "normal"
            )
        else:
            return error(f"Unknown memory type: {args.type}", "INVALID_TYPE")
        
        return success(data={"id": mem_id}, message=f"Memory added: {args.type}")
    except Exception as e:
        return error(str(e), "MEMORY_ADD_ERROR")


def cmd_memory_search(args):
    """搜索记忆"""
    try:
        mem = MemoryManager(args.project_id)
        results = mem.search(args.query, type=args.type, limit=args.limit)
        
        items = []
        for r in results:
            items.append({
                "id": r.id,
                "type": r.type,
                "content": r.content,
                "metadata": r.metadata,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None
            })
        
        return success(data={"results": items, "count": len(items)})
    except Exception as e:
        return error(str(e), "MEMORY_SEARCH_ERROR")


def cmd_memory_list(args):
    """列出所有记忆"""
    try:
        mem = MemoryManager(args.project_id)
        results = mem.get_all(type=args.type)
        
        items = []
        for r in results:
            items.append({
                "id": r.id,
                "type": r.type,
                "content": r.content[:200] + "..." if len(r.content) > 200 else r.content,
                "metadata": r.metadata
            })
        
        return success(data={"items": items, "count": len(items)})
    except Exception as e:
        return error(str(e), "MEMORY_LIST_ERROR")


# ============================================================
#                      Finding 命令
# ============================================================

def cmd_finding_add(args):
    """添加发现"""
    try:
        orch = SecurityOrchestrator(args.project_id)
        
        # 解析 JSON 输入
        if args.json:
            finding = json.loads(args.json)
        else:
            finding = {
                "title": args.title,
                "severity": args.severity or "info",
                "type": args.finding_type or "unknown",
                "location": args.location or "",
                "details": args.details or ""
            }
        
        # 直接添加到 state，避免 memory.add_finding 参数冲突
        import uuid
        finding_id = finding.get("id") or str(uuid.uuid4())
        finding["id"] = finding_id
        orch.state["findings"].append(finding)
        orch.save_state()
        
        return success(data={"id": finding_id}, message="Finding added")
    except json.JSONDecodeError as e:
        return error(f"Invalid JSON: {e}", "JSON_PARSE_ERROR")
    except Exception as e:
        return error(str(e), "FINDING_ADD_ERROR")


def cmd_finding_list(args):
    """列出发现"""
    try:
        orch = SecurityOrchestrator(args.project_id)
        findings = orch.state.get("findings", [])
        
        if args.severity:
            findings = [f for f in findings if f.get("severity") == args.severity]
        
        return success(data={"findings": findings, "count": len(findings)})
    except Exception as e:
        return error(str(e), "FINDING_LIST_ERROR")


# ============================================================
#                      Status 命令
# ============================================================

def cmd_status(args):
    """查看项目状态"""
    try:
        orch = SecurityOrchestrator(args.project_id)
        state = orch.state
        
        summary = {
            "project_id": args.project_id,
            "status": state["meta"]["status"],
            "last_updated": state["meta"]["last_updated"],
            "target": state.get("target", {}),
            "progress": {
                "phase": state["progress"]["phase"],
                "current_task": state["progress"]["current_task"],
                "completed_count": len(state["progress"]["completed_tasks"])
            },
            "findings_count": len(state.get("findings", [])),
            "explorations": {
                "tried": len(state["exploration"]["tried"]),
                "pending": len(state["exploration"]["pending"])
            }
        }
        
        if args.full:
            summary["full_state"] = state
        
        return success(data=summary)
    except Exception as e:
        return error(str(e), "STATUS_ERROR")


# ============================================================
#                      Tool 命令
# ============================================================

def cmd_tool_probe(args):
    """探测参数"""
    try:
        from .sync_wrapper import SyncBurp
        from .payloads import SQLI
        
        url = args.url
        param = args.param
        value = args.value
        
        # 每次请求用新的 burp 实例避免 event loop 问题
        def make_request(test_url):
            burp = SyncBurp(project=args.project or "ide_probe", delay=args.delay)
            try:
                return burp.get(test_url)
            finally:
                burp.close()
        
        # 获取基线
        baseline = make_request(f"{url}?{param}={value}")
        
        # 测试常见 payload
        test_payloads = ["'", '"', "' OR '1'='1", "1 AND 1=1", "1 AND 1=2"]
        errors = {}
        blocked = []
        changed = []
        
        for p in test_payloads:
            test_value = f"{value}{p}"
            try:
                r = make_request(f"{url}?{param}={test_value}")
                
                if r.error:
                    errors[p] = r.error
                if r.blocked:
                    blocked.append(p)
                if abs(r.length - baseline.length) > 50:
                    changed.append(p)
            except Exception as e:
                errors[p] = str(e)
        
        result = {
            "url": url,
            "param": param,
            "value": value,
            "baseline": {
                "status": baseline.status,
                "length": baseline.length,
                "time_ms": baseline.time_ms
            },
            "errors": errors,
            "blocked": blocked,
            "changed": changed,
            "is_numeric": value.isdigit(),
            "suggested_payloads": SQLI.quick[:5] if errors else []
        }
        
        return success(data=result)
    except Exception as e:
        return error(str(e), "PROBE_ERROR")


def cmd_tool_scan(args):
    """漏洞扫描"""
    try:
        from .sync_wrapper import SyncBurp
        from .detectors import VulnScanner
        
        burp = SyncBurp(project=args.project or "ide_scan", delay=args.delay)
        scanner = VulnScanner(burp)
        
        try:
            types = args.types.split(",") if args.types else None
            findings = scanner.scan(args.url, args.param, args.value, types=types)
            
            results = []
            for f in findings:
                results.append({
                    "vuln_type": f.vuln_type,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "payload": f.payload,
                    "details": f.details
                })
            
            return success(data={
                "url": args.url,
                "param": args.param,
                "findings": results,
                "count": len(results)
            })
        finally:
            burp.close()
    except Exception as e:
        return error(str(e), "SCAN_ERROR")


# ============================================================
#                      Exploration 命令
# ============================================================

def cmd_exploration_add(args):
    """记录探索路径"""
    try:
        orch = SecurityOrchestrator(args.project_id)
        orch.add_exploration(args.path, args.result, args.reason)
        return success(message=f"Exploration recorded: {args.path}")
    except Exception as e:
        return error(str(e), "EXPLORATION_ERROR")


def cmd_exploration_pending(args):
    """管理待探索列表"""
    try:
        orch = SecurityOrchestrator(args.project_id)
        
        if args.add:
            orch.state["exploration"]["pending"].append(args.add)
            orch.save_state()
            return success(message=f"Added to pending: {args.add}")
        elif args.remove:
            pending = orch.state["exploration"]["pending"]
            if args.remove in pending:
                pending.remove(args.remove)
                orch.save_state()
                return success(message=f"Removed from pending: {args.remove}")
            else:
                return error(f"Not found in pending: {args.remove}", "NOT_FOUND")
        else:
            return success(data={"pending": orch.state["exploration"]["pending"]})
    except Exception as e:
        return error(str(e), "PENDING_ERROR")


# ============================================================
#                      Target 命令
# ============================================================

def cmd_target_set(args):
    """设置审计目标"""
    try:
        orch = SecurityOrchestrator(args.project_id)
        orch.set_target(
            type=args.type,
            name=args.name,
            path=args.path,
            url=args.url,
            goal=args.goal or "Security Audit",
            version=args.version
        )
        return success(message="Target set", data=orch.state["target"])
    except Exception as e:
        return error(str(e), "TARGET_ERROR")


# ============================================================
#                      Agent 命令
# ============================================================

# ============================================================
#                  V4 Traffic 命令 (M7)
# ============================================================

def _run_async(coro):
    """在同步 CLI 里运行协程 (兼容已有/无 event loop 场景)"""
    import asyncio
    try:
        asyncio.get_running_loop()
        # 已在 loop 内 - 不该发生在 CLI 同步上下文, 但防御性处理
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        return asyncio.run(coro)


def cmd_traffic(args):
    """V4 traffic 层命令 (多协议 probe/scan/check)"""
    from .traffic import TrafficEngine

    if args.traffic_action == "probe":
        return _cmd_traffic_probe(args, TrafficEngine)
    elif args.traffic_action == "scan":
        return _cmd_traffic_scan(args, TrafficEngine)
    elif args.traffic_action == "check":
        return _cmd_traffic_check(args, TrafficEngine)
    elif args.traffic_action == "repeat":
        return _cmd_traffic_repeat(args, TrafficEngine)
    elif args.traffic_action == "intrude":
        return _cmd_traffic_intrude(args, TrafficEngine)
    elif args.traffic_action == "report":
        return _cmd_traffic_report(args, TrafficEngine)
    elif args.traffic_action == "revshell":
        return _cmd_traffic_revshell(args)
    else:
        return error("Unknown traffic action", "INVALID_ACTION")


def _cmd_traffic_probe(args, EngineCls):
    """traffic probe <target> - 多协议探活"""
    async def run():
        async with EngineCls() as engine:
            return await engine.smart_probe(args.target, timeout=args.timeout or 5)
    resp = _run_async(run())
    return success(resp.to_dict())


def _cmd_traffic_scan(args, EngineCls):
    """traffic scan <cidr|host> - 批量扫描"""
    async def run():
        async with EngineCls() as engine:
            # 解析端口
            ports = None
            if args.ports:
                ports = [int(p.strip()) for p in args.ports.split(",")]
            if "/" in args.target:
                return await engine.scan_cidr(
                    args.target, ports=ports,
                    concurrency=args.concurrency or 50,
                    timeout=args.timeout or 3,
                )
            else:
                # 单 host 或逗号分隔的 host 列表
                hosts = [h.strip() for h in args.target.split(",")]
                return await engine.scan_hosts(
                    hosts, ports=ports,
                    concurrency=args.concurrency or 50,
                    timeout=args.timeout or 3,
                )
    result = _run_async(run())
    # 输出格式: 默认 JSON, --text 给人类报告
    if args.text:
        return success({"report": result.report_text(only_high_value=args.high_value_only),
                        "summary": result.summary()})
    return success(result.to_dict(only_open=not args.include_closed))


def _cmd_traffic_check(args, EngineCls):
    """traffic check <target> - 一键未授权检测"""
    async def run():
        async with EngineCls() as engine:
            return await engine.check_unauth(args.target, timeout=args.timeout or 5)
    resp = _run_async(run())
    return success(resp.to_dict())


def _cmd_traffic_repeat(args, EngineCls):
    """traffic repeat - HTTP Repeater"""
    async def run():
        async with EngineCls() as engine:
            from aiburp.traffic import TrafficRequest
            headers = {}
            if args.header:
                for h in args.header:
                    k, _, v = h.partition(":")
                    headers[k.strip()] = v.strip()
            if args.cookie:
                headers["Cookie"] = args.cookie
            req = TrafficRequest(
                protocol="http", target=args.url,
                headers=headers,
                meta={"method": args.method, "data": args.data} if args.data else {"method": args.method},
            )
            return await engine.send(req)
    resp = _run_async(run())
    return success({
        "status": resp.status, "length": resp.length,
        "headers": resp.headers, "body": resp.body[:2000],
        "time_ms": resp.time_ms,
    })


def _cmd_traffic_intrude(args, EngineCls):
    """traffic intrude - HTTP Intruder (批量 fuzz)"""
    async def run():
        async with EngineCls() as engine:
            # 加载 payload
            if args.payloads in ("sqli", "xss", "lfi", "cmdi", "ssti", "ssrf"):
                from aiburp.payloads import SQLI, XSS, LFI, CMDI, SSTI, SSRF
                payloads_map = {"sqli": SQLI, "xss": XSS, "lfi": LFI,
                               "cmdi": CMDI, "ssti": SSTI, "ssrf": SSRF}
                payloads = payloads_map[args.payloads].quick
            else:
                with open(args.payloads) as f:
                    payloads = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            results = await engine.fuzz(args.url, payloads, protocol="http")
            return results
    results = _run_async(run())
    interesting = [r for r in results if r.is_interesting]
    return success({
        "total": len(results),
        "interesting": len(interesting),
        "results": [{"payload": r.payload, "status": r.status, "length": r.length,
                      "error": r.error, "interesting": r.is_interesting}
                     for r in interesting[:20]],
    })


def _cmd_traffic_report(args, EngineCls):
    """traffic report - 生成报告"""
    from aiburp.traffic.report_generator_v4 import ReportGenerator
    gen = ReportGenerator(project="aiburp-scan")
    # 这里简化: 用上次扫描结果 (实际需要持久化存储)
    gen.add_section("说明", "报告从最近一次扫描生成。完整报告请用 Python API。")
    if args.format == "html":
        gen.save_html(args.output)
    elif args.format == "md":
        gen.save_markdown(args.output)
    else:
        gen.save_json(args.output)
    return success({"output": args.output, "format": args.format})


def _cmd_traffic_revshell(args):
    """traffic revshell - 反弹 shell 生成"""
    from aiburp.traffic.revshell import ReverseShellGenerator
    gen = ReverseShellGenerator()
    payloads = gen.generate(args.ip, args.port, shell_type=args.type, encode=args.encode)
    listener = gen.get_listener(args.port)
    return success({
        "payloads": payloads,
        "listener": listener,
        "tip": "先在攻击机执行 listener, 再在目标执行 payload",
    })


# ============================================================

def cmd_agent(args):
    """Agent 模式命令"""
    from .agent import SecurityAgent, check_llm_status
    
    if args.agent_action == "status":
        return check_llm_status()
    
    elif args.agent_action == "start":
        agent = SecurityAgent(args.project_id)
        
        if not agent.is_ready:
            return error(
                "LLM 未配置，请设置 OPENAI_API_KEY 或 ANTHROPIC_API_KEY",
                "LLM_NOT_CONFIGURED"
            )
        
        agent.max_iterations = args.max_iterations
        result = agent.run(initial_instruction=args.instruction)
        return result
    
    else:
        return error("Unknown agent action", "INVALID_ACTION")


# ============================================================
#                      Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="AI-Burp IDE Mode CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--pretty", "-p", action="store_true", help="Pretty print JSON")
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # ========== prompt ==========
    prompt_parser = subparsers.add_parser("prompt", help="Get prompt for IDE")
    prompt_parser.add_argument("project_id", help="Project ID")
    prompt_parser.add_argument("--type", "-t", default="recovery",
                               choices=["recovery", "researcher", "exhaustive", "hacker", "chaos", "assumption", "intuition", "fuzz", "cthulhu"],
                               help="Prompt type: recovery(恢复), researcher(研究员), exhaustive(穷举), hacker(黑客), chaos(组合混沌), assumption(假设猎手), intuition(直觉组合), fuzz(超随机FUZZ), cthulhu(克苏鲁混沌)")
    prompt_parser.add_argument("--task", help="Task description for exhaustive mode")
    
    # ========== memory ==========
    memory_parser = subparsers.add_parser("memory", help="Memory operations")
    memory_sub = memory_parser.add_subparsers(dest="memory_action")
    
    # memory add
    mem_add = memory_sub.add_parser("add", help="Add memory")
    mem_add.add_argument("project_id", help="Project ID")
    mem_add.add_argument("type", choices=["code", "finding", "exploration", "instruction"])
    mem_add.add_argument("content", help="Content to store")
    mem_add.add_argument("--file", "-f", help="File name (for code)")
    mem_add.add_argument("--line", "-l", type=int, help="Line number")
    mem_add.add_argument("--severity", "-s", help="Severity (for finding)")
    mem_add.add_argument("--result", help="Result (for exploration)")
    mem_add.add_argument("--reason", help="Reason (for exploration)")
    mem_add.add_argument("--priority", help="Priority (for instruction)")
    
    # memory search
    mem_search = memory_sub.add_parser("search", help="Search memory")
    mem_search.add_argument("project_id", help="Project ID")
    mem_search.add_argument("query", help="Search query")
    mem_search.add_argument("--type", "-t", help="Filter by type")
    mem_search.add_argument("--limit", "-n", type=int, default=10, help="Max results")
    
    # memory list
    mem_list = memory_sub.add_parser("list", help="List all memory")
    mem_list.add_argument("project_id", help="Project ID")
    mem_list.add_argument("--type", "-t", help="Filter by type")
    
    # ========== finding ==========
    finding_parser = subparsers.add_parser("finding", help="Finding operations")
    finding_sub = finding_parser.add_subparsers(dest="finding_action")
    
    # finding add
    find_add = finding_sub.add_parser("add", help="Add finding")
    find_add.add_argument("project_id", help="Project ID")
    find_add.add_argument("--json", "-j", help="Finding as JSON")
    find_add.add_argument("--title", "-t", help="Finding title")
    find_add.add_argument("--severity", "-s", default="info",
                          choices=["critical", "high", "medium", "low", "info"])
    find_add.add_argument("--type", dest="finding_type", help="Finding type")
    find_add.add_argument("--location", "-l", help="Location (file:line)")
    find_add.add_argument("--details", "-d", help="Details")
    
    # finding list
    find_list = finding_sub.add_parser("list", help="List findings")
    find_list.add_argument("project_id", help="Project ID")
    find_list.add_argument("--severity", "-s", help="Filter by severity")
    
    # ========== status ==========
    status_parser = subparsers.add_parser("status", help="Project status")
    status_parser.add_argument("project_id", help="Project ID")
    status_parser.add_argument("--full", "-f", action="store_true", help="Full state")
    
    # ========== tool ==========
    tool_parser = subparsers.add_parser("tool", help="Security tools")
    tool_sub = tool_parser.add_subparsers(dest="tool_action")
    
    # tool probe
    tool_probe = tool_sub.add_parser("probe", help="Probe parameter")
    tool_probe.add_argument("url", help="Target URL")
    tool_probe.add_argument("param", help="Parameter name")
    tool_probe.add_argument("value", help="Parameter value")
    tool_probe.add_argument("--project", help="Project name for history")
    tool_probe.add_argument("--delay", type=float, default=1.0, help="Request delay")
    
    # tool scan
    tool_scan = tool_sub.add_parser("scan", help="Vulnerability scan")
    tool_scan.add_argument("url", help="Target URL")
    tool_scan.add_argument("param", help="Parameter name")
    tool_scan.add_argument("value", help="Parameter value")
    tool_scan.add_argument("--types", "-t", help="Vuln types (comma separated)")
    tool_scan.add_argument("--project", help="Project name")
    tool_scan.add_argument("--delay", type=float, default=1.0, help="Request delay")
    
    # ========== exploration ==========
    exp_parser = subparsers.add_parser("exploration", help="Exploration tracking")
    exp_sub = exp_parser.add_subparsers(dest="exp_action")
    
    # exploration add
    exp_add = exp_sub.add_parser("add", help="Record exploration")
    exp_add.add_argument("project_id", help="Project ID")
    exp_add.add_argument("path", help="Exploration path")
    exp_add.add_argument("result", choices=["success", "blocked", "partial", "failed"])
    exp_add.add_argument("reason", help="Reason/details")
    
    # exploration pending
    exp_pending = exp_sub.add_parser("pending", help="Manage pending list")
    exp_pending.add_argument("project_id", help="Project ID")
    exp_pending.add_argument("--add", "-a", help="Add to pending")
    exp_pending.add_argument("--remove", "-r", help="Remove from pending")
    
    # ========== target ==========
    target_parser = subparsers.add_parser("target", help="Set audit target")
    target_parser.add_argument("project_id", help="Project ID")
    target_parser.add_argument("--type", "-t", required=True,
                               choices=["whitebox", "blackbox", "greybox"])
    target_parser.add_argument("--name", "-n", help="Target name")
    target_parser.add_argument("--path", help="Code path (whitebox)")
    target_parser.add_argument("--url", "-u", help="Target URL (blackbox)")
    target_parser.add_argument("--goal", "-g", help="Audit goal (e.g., RCE)")
    target_parser.add_argument("--version", "-v", help="Target version")
    
    # ========== agent ==========
    agent_parser = subparsers.add_parser("agent", help="Agent mode (autonomous)")
    agent_sub = agent_parser.add_subparsers(dest="agent_action")
    
    # agent status - 检查 LLM 配置
    agent_status = agent_sub.add_parser("status", help="Check LLM configuration")
    
    # agent start - 启动自主审计
    agent_start = agent_sub.add_parser("start", help="Start autonomous audit")
    agent_start.add_argument("project_id", help="Project ID")
    agent_start.add_argument("--instruction", "-i", help="Initial instruction")
    agent_start.add_argument("--max-iterations", "-m", type=int, default=50, help="Max iterations")

    # ========== traffic (V4 多协议) ==========
    traffic_parser = subparsers.add_parser(
        "traffic", help="V4 multi-protocol probe/scan/check (ALL-IN-TRAFFIC)")
    traffic_sub = traffic_parser.add_subparsers(dest="traffic_action")

    # traffic probe <target>
    tp_probe = traffic_sub.add_parser("probe", help="Multi-protocol probe (auto-detect)")
    tp_probe.add_argument("target", help="Target (host:port or URL)")
    tp_probe.add_argument("--timeout", "-t", type=float, help="Timeout (sec)")

    # traffic scan <cidr|hosts>
    tp_scan = traffic_sub.add_parser("scan", help="Batch scan CIDR or host list")
    tp_scan.add_argument("target", help="CIDR (10.0.0.0/24) or host list (comma-sep)")
    tp_scan.add_argument("--ports", "-p", help="Comma-sep ports (default: high-risk set)")
    tp_scan.add_argument("--concurrency", "-c", type=int, help="Concurrency (default 50)")
    tp_scan.add_argument("--timeout", "-t", type=float, help="Per-probe timeout")
    tp_scan.add_argument("--text", action="store_true", help="Human-readable report")
    tp_scan.add_argument("--high-value-only", action="store_true", help="Only high-value assets")
    tp_scan.add_argument("--include-closed", action="store_true", help="Include closed ports")

    # traffic check <target>
    tp_check = traffic_sub.add_parser("check", help="Unauth check (redis/docker/kubelet/mysql/smb...)")
    tp_check.add_argument("target", help="Target (host:port)")
    tp_check.add_argument("--timeout", "-t", type=float, help="Timeout (sec)")

    # traffic repeat <url> (Repeater)
    tp_repeat = traffic_sub.add_parser("repeat", help="HTTP Repeater (send + modify + resend)")
    tp_repeat.add_argument("url", help="Target URL")
    tp_repeat.add_argument("--method", "-m", default="GET", help="HTTP method")
    tp_repeat.add_argument("--header", "-H", action="append", help="Headers (key:value)")
    tp_repeat.add_argument("--data", "-d", help="POST body")
    tp_repeat.add_argument("--cookie", help="Cookie header")

    # traffic intrude <url> (Intruder)
    tp_intrude = traffic_sub.add_parser("intrude", help="HTTP Intruder (batch fuzz)")
    tp_intrude.add_argument("url", help="Target URL (use § for injection point)")
    tp_intrude.add_argument("--payloads", "-p", required=True, help="Payload type: sqli/xss/lfi/cmdi or file path")
    tp_intrude.add_argument("--method", "-m", default="GET", help="HTTP method")
    tp_intrude.add_argument("--cookie", help="Cookie header")

    # traffic report <output>
    tp_report = traffic_sub.add_parser("report", help="Generate report from last scan")
    tp_report.add_argument("--output", "-o", default="report.html", help="Output file")
    tp_report.add_argument("--format", "-f", choices=["html", "md", "json"], default="html")

    # traffic revshell <ip> <port>
    tp_revshell = traffic_sub.add_parser("revshell", help="Generate reverse shell payloads")
    tp_revshell.add_argument("ip", help="Attacker IP")
    tp_revshell.add_argument("port", type=int, help="Listen port")
    tp_revshell.add_argument("--type", default="all", help="Shell type: bash/python/nc/all")
    tp_revshell.add_argument("--encode", default="raw", choices=["raw", "base64", "url"])

    # ========== Parse and execute ==========
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Route to handler
    result = None
    
    if args.command == "prompt":
        result = cmd_prompt(args)
    elif args.command == "memory":
        if args.memory_action == "add":
            result = cmd_memory_add(args)
        elif args.memory_action == "search":
            result = cmd_memory_search(args)
        elif args.memory_action == "list":
            result = cmd_memory_list(args)
        else:
            parser.print_help()
            sys.exit(1)
    elif args.command == "finding":
        if args.finding_action == "add":
            result = cmd_finding_add(args)
        elif args.finding_action == "list":
            result = cmd_finding_list(args)
        else:
            parser.print_help()
            sys.exit(1)
    elif args.command == "status":
        result = cmd_status(args)
    elif args.command == "tool":
        if args.tool_action == "probe":
            result = cmd_tool_probe(args)
        elif args.tool_action == "scan":
            result = cmd_tool_scan(args)
        else:
            parser.print_help()
            sys.exit(1)
    elif args.command == "exploration":
        if args.exp_action == "add":
            result = cmd_exploration_add(args)
        elif args.exp_action == "pending":
            result = cmd_exploration_pending(args)
        else:
            parser.print_help()
            sys.exit(1)
    elif args.command == "target":
        result = cmd_target_set(args)
    elif args.command == "agent":
        result = cmd_agent(args)
    elif args.command == "traffic":
        result = cmd_traffic(args)
    else:
        parser.print_help()
        sys.exit(1)
    
    # Output - 处理 Windows 控制台编码
    import sys
    output = json_output(result, pretty=args.pretty)
    try:
        print(output)
    except UnicodeEncodeError:
        # Windows GBK 编码问题，用 UTF-8 强制输出
        sys.stdout.buffer.write(output.encode('utf-8'))
        sys.stdout.buffer.write(b'\n')
    
    # Exit code
    if result and not result.get("ok", False):
        sys.exit(1)


if __name__ == "__main__":
    main()
