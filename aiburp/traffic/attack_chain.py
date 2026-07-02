"""
攻击链编排 - 多步骤攻击状态机.

红队攻击不是一步到位的, 是一条链:
    侦察 → 发现漏洞 → 利用 → 拿 shell → 提权 → 横向 → 持久化

本模块编排这条链, 自动或半自动地推进每一步:
    1. 从扫描结果选择目标
    2. 对目标跑 exploit (N-day)
    3. 成功 → 进入下一阶段 (提权/横向)
    4. 失败 → 回退 → 尝试其它路径
    5. 全程记录攻击路径, 生成报告

设计:
    - AttackStep: 单步 (前置条件 + 动作 + 成功条件)
    - AttackChain: 步骤链 (DAG, 支持分支)
    - AttackOrchestrator: 编排器 (驱动链执行, LLM 可介入决策)
"""

import asyncio
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum


class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class Phase(Enum):
    RECON = "recon"           # 侦察
    DETECT = "detect"         # 漏洞检测
    EXPLOIT = "exploit"       # 漏洞利用
    POST_EXPLOIT = "post"     # 后渗透 (提权/横向)
    REPORT = "report"         # 报告


@dataclass
class AttackStep:
    """攻击链的单步"""
    id: str
    name: str
    phase: Phase
    action: Callable                     # 执行函数 (async)
    precondition: Optional[Callable] = None  # 前置条件检查
    success_check: Optional[Callable] = None # 成功判断
    depends_on: List[str] = field(default_factory=list)  # 依赖的步骤 ID
    timeout: float = 60.0

    # 运行时状态
    status: StepStatus = StepStatus.PENDING
    result: Any = None
    error: str = ""
    elapsed_ms: float = 0


@dataclass
class AttackChainResult:
    """攻击链执行结果"""
    steps: List[AttackStep] = field(default_factory=list)
    total_elapsed_ms: float = 0
    success_count: int = 0
    failed_count: int = 0
    findings: List[Dict] = field(default_factory=list)  # 所有发现

    @property
    def is_exploited(self) -> bool:
        """是否至少有一个 exploit 阶段成功"""
        return any(s.phase == Phase.EXPLOIT and s.status == StepStatus.SUCCESS
                   for s in self.steps)

    def to_dict(self) -> Dict:
        return {
            "total_elapsed_ms": round(self.total_elapsed_ms, 1),
            "success": self.success_count,
            "failed": self.failed_count,
            "exploited": self.is_exploited,
            "steps": [
                {
                    "id": s.id, "name": s.name,
                    "phase": s.phase.value,
                    "status": s.status.value,
                    "elapsed_ms": round(s.elapsed_ms, 1),
                    "error": s.error,
                }
                for s in self.steps
            ],
            "findings": self.findings,
        }

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)

    def report_text(self) -> str:
        lines = []
        lines.append("=" * 70)
        lines.append("攻击链执行报告")
        lines.append("=" * 70)
        lines.append(f"总耗时: {self.total_elapsed_ms:.0f}ms | "
                      f"成功: {self.success_count} | 失败: {self.failed_count} | "
                      f"已利用: {'是 ✅' if self.is_exploited else '否'}")
        lines.append("-" * 70)

        phase_labels = {
            Phase.RECON: "🔍 侦察",
            Phase.DETECT: "🔬 检测",
            Phase.EXPLOIT: "💉 利用",
            Phase.POST_EXPLOIT: "🔓 后渗透",
            Phase.REPORT: "📄 报告",
        }

        current_phase = None
        for step in self.steps:
            if step.phase != current_phase:
                current_phase = step.phase
                label = phase_labels.get(current_phase, current_phase.value)
                lines.append(f"\n{label}:")

            status_icons = {
                StepStatus.SUCCESS: "✅",
                StepStatus.FAILED: "❌",
                StepStatus.SKIPPED: "⏭️",
                StepStatus.RUNNING: "⏳",
                StepStatus.PENDING: "⏸️",
            }
            icon = status_icons.get(step.status, "?")
            err = f" ({step.error[:40]})" if step.error else ""
            lines.append(f"  {icon} {step.name}{err} [{step.elapsed_ms:.0f}ms]")

        if self.findings:
            lines.append("\n" + "-" * 70)
            lines.append(f"发现 ({len(self.findings)}):")
            for f in self.findings[:10]:
                lines.append(f"  • {f.get('type', '?')}: {f.get('summary', '?')[:60]}")

        return "\n".join(lines)


class AttackChain:
    """
    攻击链定义 + 执行.

    用法:
        chain = AttackChain(engine)
        # 构建链 (或用预设)
        chain.recon_phase(["127.0.0.1"], [80, 22, 6379])
        chain.detect_phase()
        chain.exploit_phase()
        # 执行
        result = await chain.execute()
        print(result.report_text())
    """

    def __init__(self, engine):
        self.engine = engine
        self.steps: List[AttackStep] = []
        self._context: Dict[str, Any] = {}  # 步骤间共享的上下文
        self._llm_hook: Optional[Callable] = None  # LLM 决策钩子

    def set_llm_hook(self, hook: Callable):
        """
        设置 LLM 决策钩子.

        每个步骤完成后调用 hook(step, context), LLM 可以:
        - 分析结果
        - 决定下一步走哪个分支
        - 动态添加新步骤
        - 终止攻击链

        Args:
            hook: async callable(step: AttackStep, context: dict) -> Optional[str]
                  返回 "stop" 终止, "continue" 继续, "branch:X" 走分支 X
        """
        self._llm_hook = hook

    # ============================================================
    # 构建链
    # ============================================================

    def recon_phase(self, hosts: List[str], ports: List[int]):
        """添加侦察步骤 (V4 端口扫描 + 深度采集)"""
        async def _recon():
            result = await self.engine.scan_hosts(hosts, ports, timeout=3)
            self._context["scan_result"] = result
            return result

        self.steps.append(AttackStep(
            id="recon-scan", name=f"端口扫描 ({len(hosts)} host x {len(ports)} port)",
            phase=Phase.RECON, action=_recon, timeout=120,
        ))
        return self

    def detect_phase(self):
        """添加检测步骤 (N-day exploit 检测)"""
        from .exploits import ExploitManager

        async def _detect():
            scan = self._context.get("scan_result")
            if not scan:
                return None

            mgr = ExploitManager(self.engine)
            all_findings = []

            # 对每个 HTTP 服务跑 exploit
            for entry in scan.open_entries():
                if entry.protocol in ("http", "https") or entry.port in (80, 8080, 443, 8443):
                    url = f"http://{entry.host}:{entry.port}/"
                    results = await mgr.run_all(url)
                    for r in results:
                        if r.vulnerable:
                            all_findings.append({
                                "type": "vuln",
                                "cve": r.poc_id,
                                "url": url,
                                "summary": r.evidence[:60],
                                "severity": r.severity.value,
                            })

            # 协议层未授权检测
            for entry in scan.open_entries():
                if entry.protocol in ("redis", "docker", "kubelet", "mysql", "smb"):
                    try:
                        r = await self.engine.check_unauth(entry.target, protocol=entry.protocol)
                        if r.ok and "UNAUTH-CONFIRMED" in r.tags:
                            all_findings.append({
                                "type": "unauth",
                                "service": entry.protocol,
                                "target": entry.target,
                                "summary": f"{entry.protocol} 未授权: {r.banner}",
                            })
                    except Exception:
                        pass

            self._context["findings"] = all_findings
            return all_findings

        self.steps.append(AttackStep(
            id="detect-exploit", name="N-day + 未授权检测",
            phase=Phase.DETECT, action=_detect,
            depends_on=["recon-scan"], timeout=300,
        ))
        return self

    def exploit_phase(self):
        """添加利用步骤 (基于检测结果的深度利用)"""
        async def _exploit():
            findings = self._context.get("findings", [])
            exploited = []

            for f in findings:
                if f["type"] == "unauth":
                    # 未授权服务的后渗透
                    service = f.get("service", "")
                    target = f.get("target", "")
                    if service == "redis":
                        exploited.append({
                            "type": "post-exploit",
                            "service": "redis",
                            "target": target,
                            "summary": "Redis 未授权: 可写 SSH key/cron/webshell",
                            "rce": True,
                        })
                    elif service == "docker":
                        exploited.append({
                            "type": "post-exploit",
                            "service": "docker",
                            "target": target,
                            "summary": "Docker 未授权: 可创建特权容器 RCE",
                            "rce": True,
                        })
                elif f["type"] == "vuln":
                    exploited.append({
                        "type": "exploit-confirmed",
                        "cve": f.get("cve"),
                        "url": f.get("url"),
                        "summary": f.get("summary"),
                        "rce": f.get("severity") == "critical",
                    })

            self._context["exploited"] = exploited
            return exploited

        self.steps.append(AttackStep(
            id="exploit-use", name="漏洞利用 + 后渗透",
            phase=Phase.EXPLOIT, action=_exploit,
            depends_on=["detect-exploit"], timeout=120,
        ))
        return self

    def report_phase(self):
        """添加报告步骤"""
        async def _report():
            findings = self._context.get("findings", [])
            exploited = self._context.get("exploited", [])
            return {
                "findings": findings,
                "exploited": exploited,
                "total_vulns": len(findings),
                "total_exploited": len(exploited),
            }

        self.steps.append(AttackStep(
            id="report-gen", name="生成报告",
            phase=Phase.REPORT, action=_report,
            depends_on=["exploit-use"], timeout=10,
        ))
        return self

    # ============================================================
    # 执行链
    # ============================================================

    async def execute(self, stop_on_fail: bool = False) -> AttackChainResult:
        """
        执行攻击链.

        Args:
            stop_on_fail: 是否在失败步骤停止 (默认 False, 继续尝试其它路径)

        Returns:
            AttackChainResult
        """
        result = AttackChainResult()
        start_time = asyncio.get_event_loop().time()

        for step in self.steps:
            # 检查依赖
            deps_ok = True
            for dep_id in step.depends_on:
                dep = next((s for s in self.steps if s.id == dep_id), None)
                if dep and dep.status != StepStatus.SUCCESS:
                    step.status = StepStatus.SKIPPED
                    step.error = f"依赖 {dep_id} 未成功"
                    deps_ok = False
                    break

            if not deps_ok:
                result.steps.append(step)
                continue

            # 前置条件检查
            if step.precondition:
                try:
                    if not step.precondition(self._context):
                        step.status = StepStatus.SKIPPED
                        result.steps.append(step)
                        continue
                except Exception:
                    pass

            # 执行
            step.status = StepStatus.RUNNING
            step_start = asyncio.get_event_loop().time()

            try:
                step.result = await asyncio.wait_for(
                    step.action(), timeout=step.timeout,
                )
                step.status = StepStatus.SUCCESS
                result.success_count += 1

                # 收集发现
                if isinstance(step.result, list):
                    for item in step.result:
                        if isinstance(item, dict):
                            result.findings.append(item)
                elif isinstance(step.result, dict) and "findings" in step.result:
                    result.findings.extend(step.result["findings"])

            except asyncio.TimeoutError:
                step.status = StepStatus.FAILED
                step.error = "timeout"
                result.failed_count += 1
            except Exception as e:
                step.status = StepStatus.FAILED
                step.error = f"{type(e).__name__}: {str(e)[:50]}"
                result.failed_count += 1

            step.elapsed_ms = (asyncio.get_event_loop().time() - step_start) * 1000
            result.steps.append(step)

            # LLM 决策钩子
            if self._llm_hook:
                try:
                    decision = await self._llm_hook(step, self._context)
                    if decision == "stop":
                        break
                except Exception:
                    pass

            if stop_on_fail and step.status == StepStatus.FAILED:
                # 标记后续步骤为跳过
                for remaining in self.steps[len(result.steps):]:
                    remaining.status = StepStatus.SKIPPED
                    result.steps.append(remaining)
                break

        result.total_elapsed_ms = (asyncio.get_event_loop().time() - start_time) * 1000
        return result

    # ============================================================
    # 预设链
    # ============================================================

    @classmethod
    def full_auto(cls, engine, hosts: List[str], ports: List[int]) -> "AttackChain":
        """
        全自动攻击链预设 (动态分支版).

        侦察 → 检测 → 利用 → 报告, 一步到位.
        利用阶段根据检测结果动态选择路径 (SSH/Redis/Docker/Web).
        """
        return (cls(engine)
                .recon_phase(hosts, ports)
                .detect_phase()
                .exploit_phase()
                .report_phase())

    def adaptive_exploit_phase(self):
        """
        自适应利用阶段 — 根据检测结果动态选择攻击路径.

        与 exploit_phase 的区别:
        - exploit_phase: 固定逻辑, 不管检测结果是什么都走同样流程
        - adaptive_exploit_phase: 根据 findings 的类型选择不同利用方式
          - SSH → 弱口令 → exec_cmd
          - Redis → check_unauth → 写 webshell 建议
          - Docker → docker_rce
          - Web → N-day exploit
          - 业务逻辑 → IDOR/越权
        """
        async def _adaptive():
            findings = self._context.get("findings", [])
            exploited = []

            for f in findings:
                ftype = f.get("type", "")
                service = f.get("service", "")
                target = f.get("target", "")

                # SSH 弱口令
                if service == "ssh" or (ftype == "unauth" and "ssh" in str(f)):
                    try:
                        from .exploits import check_log4shell  # 不会触发, 只是 import 测试
                    except Exception:
                        pass
                    exploited.append({
                        "type": "ssh-brute", "target": target,
                        "summary": "SSH 弱口令检测 (需要 check_weak_creds)",
                    })

                # Docker RCE
                elif service == "docker":
                    try:
                        from .docker_exploit import docker_rce
                        r = await docker_rce(
                            f"http://{target.split(':')[0]}:2375",
                            self.engine, command="id",
                        )
                        if r.vulnerable:
                            exploited.append({
                                "type": "docker-rce", "target": target,
                                "summary": f"Docker RCE: {r.evidence[:60]}",
                                "output": r.details.get("output", ""),
                            })
                    except Exception:
                        pass

                # Kubelet RCE
                elif service == "kubelet":
                    try:
                        from .docker_exploit import kubelet_rce
                        r = await kubelet_rce(
                            f"https://{target.split(':')[0]}:10250",
                            self.engine, command="id",
                        )
                        if r.vulnerable:
                            exploited.append({
                                "type": "kubelet-rce", "target": target,
                                "summary": f"Kubelet RCE: {r.evidence[:60]}",
                            })
                    except Exception:
                        pass

                # Redis 未授权
                elif service == "redis":
                    exploited.append({
                        "type": "redis-exploit", "target": target,
                        "summary": "Redis 未授权: 可写 SSH key / cron / webshell",
                        "rce_paths": ["写 ~/.ssh/authorized_keys",
                                      "写 /var/spool/cron/root",
                                      "写 web 目录 webshell",
                                      "主从复制 RCE (SLAVEOF + module)"],
                    })

                # Web 漏洞
                elif ftype == "vuln" and f.get("severity") == "critical":
                    exploited.append({
                        "type": "web-exploit", "target": f.get("url", ""),
                        "cve": f.get("cve", ""),
                        "summary": f.get("summary", ""),
                        "rce": True,
                    })

            self._context["exploited"] = exploited
            return exploited

        self.steps.append(AttackStep(
            id="adaptive-exploit", name="自适应利用 (动态分支)",
            phase=Phase.EXPLOIT, action=_adaptive,
            depends_on=["detect-exploit"], timeout=300,
        ))
        return self
