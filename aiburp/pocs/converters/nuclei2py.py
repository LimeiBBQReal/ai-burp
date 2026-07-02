"""
Nuclei 模板转 Python POC 转换器

支持转换简单的 Nuclei 模板:
- 单请求
- 简单匹配 (word, regex, status)
- 无 DSL 表达式

使用方式:
    converter = NucleiConverter()
    
    # 转换单个模板
    poc_code = converter.convert_file("path/to/template.yaml")
    
    # 批量转换
    converter.convert_directory("nuclei-templates/cves/2024/", "output/")
    
    # 检查模板是否可自动转换
    can_convert, reason = converter.can_convert("path/to/template.yaml")
"""

import os
import re
import yaml
from typing import Tuple, Optional, List, Dict
from dataclasses import dataclass


@dataclass
class NucleiTemplate:
    """Nuclei 模板结构 (V4: 支持 http/tcp/dns 多协议)"""
    id: str
    name: str
    severity: str
    description: str
    cve: Optional[str]
    tags: List[str]
    requests: List[Dict]          # HTTP 请求 (旧字段, 保留)
    protocol: str = "http"        # V4: http / tcp / dns
    network: List[Dict] = None    # V4: tcp inputs/matchers
    dns_query: List[Dict] = None  # V4: dns queries

    @property
    def is_simple(self) -> bool:
        """是否是简单模板 (可自动转换)"""
        if self.protocol == "http":
            if len(self.requests) != 1:
                return False
            req = self.requests[0]
            if "raw" in req: return False
            if "dsl" in str(req.get("matchers", [])): return False
            if "extractors" in req and any("dsl" in str(e) for e in req["extractors"]):
                return False
            if req.get("req-condition"): return False
            return True

        # tcp / dns: 只支持单步骤 + word/regex/status matcher
        ops = self.network if self.protocol == "tcp" else self.dns_query
        if not ops or len(ops) != 1:
            return False
        matchers = ops[0].get("matchers", [])
        for m in matchers:
            if m.get("type") == "dsl":
                return False
        return True


class NucleiConverter:
    """Nuclei 模板转换器"""

    # Severity 白名单 - 与 poc_manager.Severity 枚举一致
    # 非法值 (如 "unknown"/"warning"/拼写错误) 降级为 INFO, 避免 AttributeError
    VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

    @classmethod
    def _normalize_severity(cls, severity: str) -> str:
        """归一化 severity 为 Severity 枚举成员名, 非法值降级 INFO"""
        s = (severity or "").upper().strip()
        return s if s in cls.VALID_SEVERITIES else "INFO"

    @staticmethod
    def _safe_for_docstring(s: str) -> str:
        """
        把任意字符串转成可安全放入 Python docstring 的内容.

        防止 nuclei 模板的 name/description 含 \"\"\" 或 \\n 注入代码:
        生成代码时这些字段被拼进 docstring, 若含 \"\"\" 会闭合字符串,
        后续内容被当 Python 代码执行 (代码注入 RCE).

        策略: 剔除/替换所有可能逃逸 docstring 的字符.
        """
        if not s:
            return ""
        # 1. 去掉三引号 (任何数量连续的 \" 都压缩成空)
        cleaned = s.replace('"""', '').replace("'''", "")
        # 2. 单独的 \" 也替换掉 (防止 \"\"\" 的变体)
        #    但保留正常文本里的单引号
        # 3. 控制字符替换为空格 (防止 \\n 等破坏代码结构)
        cleaned = "".join(
            ch if (ch.isprintable() or ch in "\n\t") else " "
            for ch in cleaned
        )
        # 4. 长度限制 (防止超长 description 撑爆生成代码)
        return cleaned[:500]

    def __init__(self):
        self.template_header = '''"""
Auto-generated from Nuclei template: {template_id}
CVE: {cve}
Severity: {severity}

{description}
"""

import requests
import re
from urllib.parse import urljoin
from ..poc_manager import POCInfo, POCResult, POCLevel, Severity

'''
    
    def parse_template(self, yaml_path: str) -> Optional[NucleiTemplate]:
        """解析 Nuclei YAML 模板"""
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
            
            if not data:
                return None
            
            info = data.get("info", {})
            
            # 提取 CVE
            cve = None
            classification = info.get("classification", {})
            if classification:
                cve = classification.get("cve-id")
            if not cve:
                # 从 ID 中提取
                template_id = data.get("id", "")
                if template_id.upper().startswith("CVE-"):
                    cve = template_id.upper()
            
            # V4: 识别协议 (http/tcp/dns). Nuclei 模板用顶层字段名区分.
            http_reqs = data.get("http") or data.get("requests") or []
            tcp_ops = data.get("tcp") or []
            dns_ops = data.get("dns") or []

            if tcp_ops:
                protocol = "tcp"
            elif dns_ops:
                protocol = "dns"
            else:
                protocol = "http"

            return NucleiTemplate(
                id=data.get("id", "unknown"),
                name=info.get("name", "Unknown"),
                severity=info.get("severity", "unknown"),
                description=info.get("description", ""),
                cve=cve,
                tags=info.get("tags", []) if isinstance(info.get("tags"), list) else info.get("tags", "").split(","),
                requests=http_reqs,
                protocol=protocol,
                network=tcp_ops,
                dns_query=dns_ops,
            )
        except Exception as e:
            print(f"解析失败: {yaml_path} - {e}")
            return None
    
    @staticmethod
    def _has_negative_matcher(matchers: List[Dict]) -> bool:
        """检测是否含 negative matcher (匹配=不算漏洞, 语义反转, 自动转换易出错)"""
        return any(m.get("negative") for m in matchers)

    def can_convert(self, yaml_path: str) -> Tuple[bool, str]:
        """检查模板是否可自动转换 (V4: 支持 http/tcp/dns)"""
        template = self.parse_template(yaml_path)

        if not template:
            return False, "无法解析模板"

        if template.protocol == "http":
            if not template.requests:
                return False, "没有 HTTP 请求"
            if len(template.requests) > 1:
                return False, "多步骤 HTTP 请求 (需要手工转换)"
            req = template.requests[0]
            if "raw" in req:
                return False, "Raw HTTP 请求 (需要手工转换)"
            matchers = req.get("matchers", [])
            for matcher in matchers:
                if matcher.get("type") == "dsl":
                    return False, "DSL 匹配器 (需要手工转换)"
            if self._has_negative_matcher(matchers):
                return False, "Negative matcher (语义反转, 需手工转换避免误报)"
            if req.get("req-condition"):
                return False, "条件请求 (需要手工转换)"
            return True, "可以自动转换 (http)"

        if template.protocol == "tcp":
            if not template.network:
                return False, "没有 tcp 操作"
            if len(template.network) > 1:
                return False, "多步骤 tcp (需要手工转换)"
            matchers = template.network[0].get("matchers", [])
            for m in matchers:
                if m.get("type") == "dsl":
                    return False, "DSL 匹配器 (需要手工转换)"
            if self._has_negative_matcher(matchers):
                return False, "Negative matcher (语义反转, 需手工转换避免误报)"
            return True, "可以自动转换 (tcp)"

        if template.protocol == "dns":
            if not template.dns_query:
                return False, "没有 dns 查询"
            if len(template.dns_query) > 1:
                return False, "多步骤 dns (需要手工转换)"
            matchers = template.dns_query[0].get("matchers", [])
            if self._has_negative_matcher(matchers):
                return False, "Negative matcher (语义反转, 需手工转换避免误报)"
            return True, "可以自动转换 (dns)"

        return False, f"未知协议: {template.protocol}"
    
    def convert_file(self, yaml_path: str) -> Optional[str]:
        """转换单个模板为 Python 代码 (V4: 按 protocol 分派)"""
        can, reason = self.can_convert(yaml_path)
        if not can:
            print(f"无法自动转换: {reason}")
            return None

        template = self.parse_template(yaml_path)
        if not template:
            return None

        if template.protocol == "tcp":
            return self._generate_tcp_code(template)
        if template.protocol == "dns":
            return self._generate_dns_code(template)
        return self._generate_code(template)   # http

    # ============================================================
    # V4: TCP 模板 -> 用 UPM TcpAdapter
    # ============================================================

    def _generate_tcp_code(self, template: NucleiTemplate) -> str:
        """生成基于 UPM TcpAdapter 的 POC"""
        op = template.network[0]
        func_name = f"check_{template.id.replace('-', '_').replace('.', '_').lower()}"

        # inputs -> payload bytes (Nuclei: [{data: 'INFO\r\n'}])
        inputs = op.get("inputs", [])
        payload_repr = repr(inputs[0].get("data", "")) if inputs else repr("")

        # matchers
        matchers = op.get("matchers", [])
        matchers_condition = op.get("matchers-condition", "or")

        code = []
        code.append(self.template_header.format(
            template_id=self._safe_for_docstring(template.id),
            cve=self._safe_for_docstring(template.cve or "N/A"),
            severity=template.severity,
            description=self._safe_for_docstring(template.description),
        ))
        code.append(f'''
import re
import asyncio


def _run_async(coro):
    """
    在同步上下文运行协程.
    若当前线程已有运行中的 event loop (如 Agent 模式), 抛 RuntimeError
    提示调用方改用 await _{func_name}_async() —— 避免跨 loop 创建 adapter.
    抛错前会先 close 协程, 防止 'coroutine was never awaited' 警告.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # 没有运行中的 loop, 正常用 asyncio.run
        return asyncio.run(coro)
    # 走到这里说明检测到运行中的 loop - 先关闭协程再抛错
    coro.close()
    raise RuntimeError(
        "已存在运行中的 event loop. 请改用 await _{func_name}_async(target, timeout) "
        "或在新线程中调用同步版本."
    )


async def _{func_name}_async(target: str, timeout: float = 5):
    """async 原生实现, 供 async 调用方直接 await."""
    from aiburp.traffic.adapters import TcpAdapter
    from aiburp.traffic import TrafficRequest
    async with TcpAdapter(timeout=timeout) as adapter:
        req = TrafficRequest(protocol="tcp", target=target, payload={payload_repr})
        return await adapter.send(req)


def {func_name}(target: str, **kwargs) -> "POCResult":
    """检测 {self._safe_for_docstring(template.name)} (TCP, sync wrapper)"""
    resp = _run_async(_{func_name}_async(target, kwargs.get("timeout", 5)))

    if not resp.ok:
        return POCResult(poc_id={repr(template.id)}, name={repr(template.name)}, vulnerable=False)

    matches = []
''')

        # 生成 matcher 检测
        for i, m in enumerate(matchers):
            mt = m.get("type", "word")
            if mt == "word":
                words = m.get("words", [])
                cond = m.get("condition", "or")
                tgt = "resp.text"
                joiner = "all" if cond == "and" else "any"
                code.append(f"    match_{i} = {joiner}(w in {tgt} for w in {words})")
                code.append(f"    matches.append(match_{i})")
            elif mt == "regex":
                regs = m.get("regex", [])
                code.append(f"    match_{i} = any(re.search(r, resp.text) for r in {regs})")
                code.append(f"    matches.append(match_{i})")

        joiner = "all" if matchers_condition == "and" else "any"
        code.append(f"    if {joiner}(matches):")
        code.append(f"        return POCResult(")
        code.append(f"            poc_id={repr(template.id)},")
        code.append(f"            name={repr(template.name)},")
        code.append(f"            vulnerable=True,")
        code.append(f"            severity=Severity.{self._normalize_severity(template.severity)},")
        code.append(f"            evidence=f'TCP banner/text 命中',")
        code.append(f"            details={{'banner': resp.banner, 'text': resp.text[:200]}}")
        code.append(f"        )")
        code.append(f"    return POCResult(poc_id={repr(template.id)}, name={repr(template.name)}, vulnerable=False)")
        code.append("")
        code.append(self._poc_info_block(template, func_name, "L2_NUCLEI_AUTO"))
        return "\n".join(code)

    # ============================================================
    # V4: DNS 模板 -> 用 UPM DnsAdapter
    # ============================================================

    def _generate_dns_code(self, template: NucleiTemplate) -> str:
        """生成基于 UPM DnsAdapter 的 POC"""
        op = template.dns_query[0]
        func_name = f"check_{template.id.replace('-', '_').replace('.', '_').lower()}"

        # Nuclei dns: [{name: '{{FQDN}}', type: A, recursion: true, ...}]
        qname_tpl = repr(op.get("name", "{{FQDN}}"))
        rdtype = op.get("type", "A")
        matchers = op.get("matchers", [])
        matchers_condition = op.get("matchers-condition", "or")

        code = []
        code.append(self.template_header.format(
            template_id=self._safe_for_docstring(template.id),
            cve=self._safe_for_docstring(template.cve or "N/A"),
            severity=template.severity,
            description=self._safe_for_docstring(template.description),
        ))
        code.append(f'''
import re
import asyncio


def _run_async(coro):
    """
    在同步上下文运行协程.
    若当前线程已有运行中的 event loop, 抛 RuntimeError 提示改用 async 版本.
    抛错前 close 协程防止泄漏.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    coro.close()
    raise RuntimeError(
        "已存在运行中的 event loop. 请改用 await _{func_name}_async(target, timeout) "
        "或在新线程中调用同步版本."
    )


async def _{func_name}_async(target: str, timeout: float = 5):
    """async 原生实现, 供 async 调用方直接 await."""
    from aiburp.traffic.adapters import DnsAdapter
    from aiburp.traffic import TrafficRequest
    async with DnsAdapter(timeout=timeout) as adapter:
        qname = {qname_tpl}.replace("{{{{FQDN}}}}", target).replace("{{{{Hostname}}}}", target)
        req = TrafficRequest(protocol="dns", target=target,
                             payload=qname, meta={{"rdtype": {repr(rdtype)}}})
        return await adapter.send(req)


def {func_name}(target: str, **kwargs) -> "POCResult":
    """检测 {self._safe_for_docstring(template.name)} (DNS, sync wrapper)"""
    resp = _run_async(_{func_name}_async(target, kwargs.get("timeout", 5)))

    if not resp.ok:
        return POCResult(poc_id={repr(template.id)}, name={repr(template.name)}, vulnerable=False)

    matches = []
''')
        for i, m in enumerate(matchers):
            mt = m.get("type", "word")
            if mt == "word":
                words = m.get("words", [])
                cond = m.get("condition", "or")
                joiner = "all" if cond == "and" else "any"
                code.append(f"    match_{i} = {joiner}(w in resp.text for w in {words})")
                code.append(f"    matches.append(match_{i})")
            elif mt == "regex":
                regs = m.get("regex", [])
                code.append(f"    match_{i} = any(re.search(r, resp.text) for r in {regs})")
                code.append(f"    matches.append(match_{i})")

        joiner = "all" if matchers_condition == "and" else "any"
        code.append(f"    if {joiner}(matches):")
        code.append(f"        return POCResult(")
        code.append(f"            poc_id={repr(template.id)},")
        code.append(f"            name={repr(template.name)},")
        code.append(f"            vulnerable=True,")
        code.append(f"            severity=Severity.{self._normalize_severity(template.severity)},")
        code.append(f"            evidence=f'DNS 记录命中',")
        code.append(f"            details={{'text': resp.text[:200]}}")
        code.append(f"        )")
        code.append(f"    return POCResult(poc_id={repr(template.id)}, name={repr(template.name)}, vulnerable=False)")
        code.append("")
        code.append(self._poc_info_block(template, func_name, "L2_NUCLEI_AUTO"))
        return "\n".join(code)

    def _poc_info_block(self, template: NucleiTemplate, func_name: str, level: str) -> str:
        """生成 POC_INFO 注册块 (http/tcp/dns 共用).

        安全: 所有从模板来的字符串字段一律用 repr() 包裹, 防止代码注入.
        repr() 会把任意字符串转成合法 Python 字面量 (含引号/反斜杠转义).
        """
        # tags 统一成 list[str], 再 repr
        safe_tags = [str(t) for t in template.tags] if template.tags else []
        return f"""
# POC 注册信息
POC_INFO = POCInfo(
    id={repr(template.id)},
    name={repr(template.name)},
    level=POCLevel.{level},
    severity=Severity.{self._normalize_severity(template.severity)},
    cve={repr(template.cve)},
    tags={repr(safe_tags)},
    description={repr(self._safe_for_docstring(template.description))},
    check_func={func_name}
)
"""

    # ============================================================
    # 原有: HTTP 模板生成 (逻辑不变, 仅挪位置)
    # ============================================================

    def _generate_code(self, template: NucleiTemplate) -> str:
        """生成 Python POC 代码"""
        req = template.requests[0]
        
        # 函数名
        func_name = f"check_{template.id.replace('-', '_').replace('.', '_').lower()}"
        
        # 请求方法和路径
        method = req.get("method", "GET").upper()
        paths = req.get("path", [])
        if isinstance(paths, str):
            paths = [paths]
        
        # 匹配器
        matchers = req.get("matchers", [])
        matchers_condition = req.get("matchers-condition", "or")
        
        # 生成代码
        code_lines = []
        
        # 头部
        code_lines.append(self.template_header.format(
            template_id=self._safe_for_docstring(template.id),
            cve=self._safe_for_docstring(template.cve or "N/A"),
            severity=template.severity,
            description=self._safe_for_docstring(template.description)
        ))
        
        # 函数定义
        code_lines.append(f"def {func_name}(url: str, **kwargs) -> POCResult:")
        code_lines.append(f'    """检测 {self._safe_for_docstring(template.name)}"""')
        code_lines.append(f"    ")
        
        # 路径列表
        code_lines.append(f"    paths = {paths}")
        code_lines.append(f"    ")
        code_lines.append(f"    for path in paths:")
        code_lines.append(f"        try:")
        code_lines.append(f"            target = path.replace('{{{{BaseURL}}}}', url.rstrip('/'))")
        
        # 请求
        if method == "GET":
            code_lines.append(f"            resp = requests.get(target, timeout=10, verify=False)")
        else:
            body = req.get("body", "")
            code_lines.append(f"            resp = requests.{method.lower()}(target, data={repr(body)}, timeout=10, verify=False)")
        
        code_lines.append(f"            ")
        
        # 匹配逻辑
        code_lines.append(f"            # 匹配检测")
        code_lines.append(f"            matches = []")
        
        for i, matcher in enumerate(matchers):
            matcher_type = matcher.get("type", "word")
            
            if matcher_type == "word":
                words = matcher.get("words", [])
                part = matcher.get("part", "body")
                condition = matcher.get("condition", "or")
                
                if part == "header":
                    check_target = "str(resp.headers)"
                else:
                    check_target = "resp.text"
                
                if condition == "and":
                    code_lines.append(f"            match_{i} = all(w in {check_target} for w in {words})")
                else:
                    code_lines.append(f"            match_{i} = any(w in {check_target} for w in {words})")
                code_lines.append(f"            matches.append(match_{i})")
            
            elif matcher_type == "regex":
                regex_list = matcher.get("regex", [])
                part = matcher.get("part", "body")
                
                if part == "header":
                    check_target = "str(resp.headers)"
                else:
                    check_target = "resp.text"
                
                code_lines.append(f"            match_{i} = any(re.search(r, {check_target}) for r in {regex_list})")
                code_lines.append(f"            matches.append(match_{i})")
            
            elif matcher_type == "status":
                status_list = matcher.get("status", [])
                code_lines.append(f"            match_{i} = resp.status_code in {status_list}")
                code_lines.append(f"            matches.append(match_{i})")
        
        # 判断结果
        code_lines.append(f"            ")
        if matchers_condition == "and":
            code_lines.append(f"            if all(matches):")
        else:
            code_lines.append(f"            if any(matches):")
        
        code_lines.append(f"                return POCResult(")
        code_lines.append(f"                    poc_id={repr(template.id)},")
        code_lines.append(f"                    name={repr(template.name)},")
        code_lines.append(f"                    vulnerable=True,")
        code_lines.append(f"                    severity=Severity.{self._normalize_severity(template.severity)},")
        code_lines.append(f"                    evidence=f'路径: {{path}}',")
        code_lines.append(f"                    details={{'path': path}}")
        code_lines.append(f"                )")
        
        code_lines.append(f"        except Exception as e:")
        code_lines.append(f"            continue")
        code_lines.append(f"    ")
        code_lines.append(f"    return POCResult(")
        code_lines.append(f"        poc_id={repr(template.id)},")
        code_lines.append(f"        name={repr(template.name)},")
        code_lines.append(f"        vulnerable=False")
        code_lines.append(f"    )")
        code_lines.append(f"")

        # POC 注册信息 (复用通用块)
        code_lines.append(self._poc_info_block(template, func_name, "L2_NUCLEI_AUTO"))

        return "\n".join(code_lines)
    
    def convert_directory(self, input_dir: str, output_dir: str, severity_filter: List[str] = None) -> Dict:
        """批量转换目录下的模板"""
        if severity_filter is None:
            severity_filter = ["critical", "high"]
        
        stats = {
            "total": 0,
            "converted": 0,
            "skipped": 0,
            "failed": 0,
            "skipped_reasons": {}
        }
        
        os.makedirs(output_dir, exist_ok=True)
        
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                if not file.endswith(".yaml"):
                    continue
                
                stats["total"] += 1
                yaml_path = os.path.join(root, file)
                
                # 解析模板
                template = self.parse_template(yaml_path)
                if not template:
                    stats["failed"] += 1
                    continue
                
                # 过滤严重程度
                if template.severity.lower() not in severity_filter:
                    stats["skipped"] += 1
                    reason = f"severity={template.severity}"
                    stats["skipped_reasons"][reason] = stats["skipped_reasons"].get(reason, 0) + 1
                    continue
                
                # 检查是否可转换
                can, reason = self.can_convert(yaml_path)
                if not can:
                    stats["skipped"] += 1
                    stats["skipped_reasons"][reason] = stats["skipped_reasons"].get(reason, 0) + 1
                    continue
                
                # 转换
                code = self._generate_code(template)
                if code:
                    output_file = os.path.join(output_dir, f"{template.id}.py")
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(code)
                    stats["converted"] += 1
                else:
                    stats["failed"] += 1
        
        return stats


# 命令行入口
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("用法: python nuclei2py.py <template.yaml>")
        print("      python nuclei2py.py <input_dir> <output_dir>")
        sys.exit(1)
    
    converter = NucleiConverter()
    
    if len(sys.argv) == 2:
        # 单文件转换
        yaml_path = sys.argv[1]
        can, reason = converter.can_convert(yaml_path)
        print(f"可转换: {can} ({reason})")
        
        if can:
            code = converter.convert_file(yaml_path)
            print("\n" + "=" * 60)
            print(code)
    else:
        # 批量转换
        input_dir = sys.argv[1]
        output_dir = sys.argv[2]
        stats = converter.convert_directory(input_dir, output_dir)
        
        print(f"\n转换统计:")
        print(f"  总数: {stats['total']}")
        print(f"  成功: {stats['converted']}")
        print(f"  跳过: {stats['skipped']}")
        print(f"  失败: {stats['failed']}")
        print(f"\n跳过原因:")
        for reason, count in stats["skipped_reasons"].items():
            print(f"  {reason}: {count}")
