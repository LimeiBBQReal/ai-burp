"""
DNS 协议适配器 - 把 DNS 当作注入点和攻击面.

不同于 aiburp.plugins.dns_validator (做域名真实性/通配符验证 - 侦察层),
本 adapter 把 DNS 作为协议层攻击面:

    1. probe()      - SOA/NS 查询 + version.bind 指纹 (BIND CHAOS)
    2. send()       - 任意 rdtype 查询 (payload 作为查询名)
    3. fuzz()       - 查询名 marker 替换, 批量探测
    4. axfr()       - 区传送 (zone transfer) - 独立高危向量
    5. DNS Rebinding - 配合 OOB 做 SSRF 白名单绕过 (M2 起接入)

典型攻击场景:
    - 内网 DNS (port 53) 暴露 -> 信息泄露 + 内网拓扑
    - AXFR 允许任意人 -> 整个 zone 泄露
    - DNS 隧道外带 -> 无回显注入的回显通道
    - DNS Rebinding -> 绕 SSRF 白名单 / 绕过同源策略

依赖: dnspython (requirements.txt 已声明)
"""

import asyncio
import dns.resolver
import dns.query
import dns.message
import dns.zone
import dns.rdatatype
import dns.exception
from typing import List, Optional

from ..base import (
    TrafficRequest,
    TrafficResponse,
    ProtocolAdapter,
)
from .fingerprints import split_host_port


class DnsAdapter(ProtocolAdapter):
    """
    DNS 协议适配器.

    用法:
        adapter = DnsAdapter(nameserver="8.8.8.8")
        resp = await adapter.probe("example.com")           # SOA/NS + version
        resp = await adapter.send(TrafficRequest(
            protocol="dns", target="example.com",
            payload="admin.example.com",                    # 查询名
            meta={"rdtype": "CNAME"}                        # 记录类型
        ))
        zone = await adapter.axfr("example.com", "ns1.example.com")
    """

    protocol = "dns"
    description = "DNS adapter (query / AXFR / version fingerprint)"

    # 常用 DNS 服务器 (默认使用系统配置)
    DEFAULT_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]

    def __init__(
        self,
        nameserver: Optional[str] = None,
        timeout: float = 5.0,
        concurrency: int = 10,
        port: int = 53,
    ):
        """
        Args:
            nameserver: 指定 DNS 服务器 IP (None = 用系统默认)
            timeout:    查询超时 (秒)
            concurrency: 并发上限
            port:       DNS 服务端口 (默认 53)
        """
        super().__init__(timeout=timeout, concurrency=concurrency)
        self.nameserver = nameserver
        self.port = port
        self._sem = asyncio.Semaphore(concurrency)
        self._resolver = self._build_resolver()
        self._closed = False

    def _check_closed(self, target: str = ""):
        if self._closed:
            return TrafficResponse(
                protocol="dns", ok=False, status=0,
                target=target, error="adapter-closed",
                anomalies=["adapter 已 close"],
            )
        return None

    def _build_resolver(self) -> dns.resolver.Resolver:
        """构造 resolver, 配置 nameserver"""
        r = dns.resolver.Resolver()
        r.timeout = self.timeout
        r.lifetime = self.timeout + 2
        if self.nameserver:
            r.nameservers = [self.nameserver]
        return r

    # ============================================================
    #                         probe
    # ============================================================

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """
        探活 + 指纹.
        - target 是域名时: 查 SOA + NS, 探 version.bind
        - target 是 host:port (DNS 服务器) 时: 用 nameserver=target 查版本

        三个查询独立成败, 互不影响 (避免单个超时拖垮整体).
        """
        closed = self._check_closed(target)
        if closed:
            return closed
        nameserver = kw.get("nameserver", self.nameserver)
        # 解析 target:
        #   - "example.com"          -> domain=example.com
        #   - "8.8.8.8:53"           -> domain=8.8.8.8 (作为 nameserver 查版本)
        #   - "dns://8.8.8.8:53"     -> 剥 scheme -> 8.8.8.8:53
        #   - "dns://example.com"    -> 剥 scheme -> example.com
        clean = target
        if "://" in clean:
            clean = clean.split("://", 1)[1]
        # 此时 clean 可能是 "host:port" 或 "domain"
        host_part, port = split_host_port(clean)
        domain = host_part

        async with self._sem:
            start = asyncio.get_event_loop().time()

            # 三个查询各自独立 await + 独立 try/except, 不让一个失败拖垮全部
            soa = await self._safe_probe(lambda: self._safe_resolve(domain, "SOA", nameserver))
            ns_records = await self._safe_probe(lambda: self._safe_resolve(domain, "NS", nameserver))
            version = await self._safe_probe(
                lambda: self._query_version_bind(nameserver or domain)
            )

            elapsed = (asyncio.get_event_loop().time() - start) * 1000

        text_parts = []
        banner_parts = []
        # _safe_resolve 现在返回 (records, status_tag), 解构
        soa_records = soa[0] if soa else []
        ns_list = ns_records[0] if ns_records else []

        if soa_records:
            text_parts.append(f"SOA: {soa_records}")
            banner_parts.append(soa_records[0].split()[0] if soa_records[0] else "")
        if ns_list:
            text_parts.append(f"NS: {', '.join(ns_list)}")
            banner_parts.append(f"{len(ns_list)}ns")
        if version:
            text_parts.append(f"version.bind: {version}")
            banner_parts.append(f"bind:{version[:20]}")

        # 三者全空才视为失败
        ok = bool(soa_records or ns_list or version)

        tags = ["DNS"]
        if version:
            tags.append("BIND-LEAKED")  # version.bind 暴露 = 信息泄露
        if ok and not soa_records and not ns_list:
            tags.append("NO-AUTHORITY")

        anomalies = []
        if version:
            anomalies.append("version-leaked")
        if not ok:
            anomalies.append("all-queries-failed")

        return TrafficResponse(
            protocol="dns",
            ok=ok,
            status=0 if ok else 2,  # DNS rcode 约定: 0=NOERROR, 2=SERVFAIL
            text="\n".join(text_parts),
            banner=" ".join(b for b in banner_parts if b),
            time_ms=elapsed,
            target=target,
            tags=tags,
            anomalies=anomalies,
            error="" if ok else "dns-all-queries-failed",
        )

    async def _safe_probe(self, sync_fn):
        """把同步 DNS 查询包成独立 try; 任一异常返回 None."""
        try:
            return await asyncio.to_thread(sync_fn)
        except Exception:
            return None

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """
        发送 DNS 查询.

        req.target: 域名 (用于 resolver 上下文, 可与 nameserver 不同)
        req.payload: 查询名 (qname). None 时用 target.
        req.meta.rdtype: 记录类型 (A/AAAA/CNAME/MX/TXT/NS/SOA/PTR/SRV/ANY...),
                          默认 "A"
        req.meta.nameserver: 指定本次查询的 DNS 服务器 (覆盖全局)
        """
        nameserver = req.meta.get("nameserver", kw.get("nameserver", self.nameserver))
        rdtype = req.meta.get("rdtype", "A")
        qname = req.payload or req.target

        closed = self._check_closed(req.target)
        if closed:
            return closed

        async with self._sem:
            start = asyncio.get_event_loop().time()
            try:
                answers, status_tag = await asyncio.to_thread(
                    self._safe_resolve, qname, rdtype, nameserver
                )
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
            except dns.exception.DNSException as e:
                # 网络超时/无应答 - 单条查询失败不崩 fuzz
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                return TrafficResponse(
                    protocol="dns", ok=False, status=2,
                    target=req.target, payload=str(qname),
                    error=f"dns-{type(e).__name__}",
                    time_ms=elapsed,
                    anomalies=["dns-query-failed"],
                )
            except Exception as e:
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
                return TrafficResponse(
                    protocol="dns", ok=False, status=0,
                    target=req.target, payload=str(qname),
                    error=str(e),
                    time_ms=elapsed,
                )

        text = "\n".join(answers) if answers else ""
        reflects = bool(qname and any(qname in a for a in answers))

        # resolved 记录数 + DNS 语义状态放 anomalies, 让 AI 能区分
        # nxdomain/no-answer/no-record/ok 四种情况
        anomalies = []
        if answers:
            anomalies.append(f"resolved:{len(answers)}records")
        anomalies.append(f"dns-status:{status_tag}")

        return TrafficResponse(
            protocol="dns",
            ok=True,
            status=0,
            text=text,
            length=len(text.encode()),
            time_ms=elapsed,
            target=req.target,
            payload=str(qname),
            reflects=reflects,
            anomalies=anomalies,
        )

    # ============================================================
    #                         fuzz
    # ============================================================

    async def fuzz(
        self,
        target: str,
        payloads: List[str],
        marker: str = "§",
        base: Optional[TrafficRequest] = None,
        **kw,
    ) -> List[TrafficResponse]:
        """
        并发 DNS fuzz.
        典型: 子域名爆破 (target=base_domain, payloads=子域名前缀, rdtype=A)
        """
        if base is None:
            base = TrafficRequest(protocol="dns", target=target)

        tasks = []
        for p in payloads:
            req = self._inject_into_request(base, p, marker)
            tasks.append(self.send(req, **kw))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        out = []
        for p, r in zip(payloads, results):
            if isinstance(r, Exception):
                out.append(TrafficResponse(
                    protocol="dns", ok=False, error=str(r),
                    target=target, payload=str(p),
                ))
            else:
                out.append(r)
        return out

    # ============================================================
    #                     axfr (区传送)
    # ============================================================

    async def axfr(
        self,
        domain: str,
        nameserver: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> TrafficResponse:
        """
        DNS 区传送 (Zone Transfer) 测试.

        AXFR 若允许任意人 -> 整个 zone 记录泄露 (高危, 通常 CVSS 7+).

        Args:
            domain:     要区传送的域名
            nameserver: 该域的权威 NS (None = 自动从 NS 记录查)
            timeout:    超时 (秒)

        Returns:
            TrafficResponse, text 里是 zone 记录, banner 是记录条数.
        """
        timeout = timeout or self.timeout

        # 自动取 NS
        if not nameserver:
            ns_records, _status = await asyncio.to_thread(
                self._safe_resolve, domain, "NS", self.nameserver
            )
            if not ns_records:
                return TrafficResponse(
                    protocol="dns", ok=False, status=0,
                    target=domain, error="no-ns-found",
                    anomalies=["cannot-resolve-ns"],
                )
            nameserver = ns_records[0].rstrip(".")

        async with self._sem:
            start = asyncio.get_event_loop().time()
            try:
                zone = await asyncio.to_thread(self._do_xfr, domain, nameserver, timeout)
                elapsed = (asyncio.get_event_loop().time() - start) * 1000
            except dns.exception.DNSException as e:
                # REFUSED / NOTIMP / 超时 -> 拒绝区传送 (这是正常的安全状态)
                # 语义: ok=False (查询未成功), 但 anomalies 标注 "secure"
                # 让上层用 if resp.ok 判断"区传送成功=漏洞" 时正确
                return TrafficResponse(
                    protocol="dns", ok=False, status=5,  # DNS rcode 5=REFUSED
                    target=domain, banner="axfr-refused",
                    error=f"axfr-refused: {type(e).__name__}",
                    anomalies=["axfr-secure"],  # 被拒绝 = 安全配置
                    time_ms=(asyncio.get_event_loop().time() - start) * 1000,
                )
            except Exception as e:
                return TrafficResponse(
                    protocol="dns", ok=False, status=0,
                    target=domain, error=str(e),
                )

        if zone is None:
            return TrafficResponse(
                protocol="dns", ok=False, status=0,
                target=domain, error="axfr-empty",
            )

        # 序列化 zone
        records = []
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset:
                    records.append(
                        f"{str(name):40s} {dns.rdatatype.to_text(rdataset.rdtype):8s} {rdata.to_text()}"
                    )

        return TrafficResponse(
            protocol="dns",
            ok=True,
            status=0,
            text="\n".join(records),
            banner=f"axfr:{len(records)}records",
            time_ms=elapsed,
            target=f"{domain}@{nameserver}",
            tags=["DNS", "AXFR-SUCCESS", "HIGH-VALUE"],
            anomalies=[f"zone-leaked:{len(records)}records"],
        )

    # ============================================================
    #                     内部: 查询原语
    # ============================================================

    def _safe_resolve(
        self,
        qname: str,
        rdtype: str,
        nameserver: Optional[str],
    ) -> tuple:
        """
        同步 DNS 解析 (在 to_thread 中调用).

        Returns:
            (records, status_tag) 二元组:
                records:    记录文本列表 (可能为空)
                status_tag: 语义化状态, 供 AI 区分:
                    "ok"        - 查询成功且有记录
                    "nxdomain"  - 域名不存在 (rcode 3)
                    "no-answer" - 域名存在但该类型无记录
                    "no-record" - 兜底: 成功但无记录

        网络异常 (超时/无NS/SERVFAIL) 向上抛, 由调用方处理.
        """
        resolver = self._resolver
        if nameserver and nameserver != self.nameserver:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [nameserver]
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout + 2

        try:
            rdtype_int = dns.rdatatype.from_text(rdtype)
        except dns.exception.SyntaxError:
            rdtype_int = dns.rdatatype.A

        try:
            answer = resolver.resolve(qname, rdtype_int)
            records = [r.to_text() for r in answer]
            return (records, "ok" if records else "no-record")
        except dns.resolver.NXDOMAIN:
            return ([], "nxdomain")  # 域名不存在
        except dns.resolver.NoAnswer:
            return ([], "no-answer")  # 该类型无记录
        except dns.resolver.NoNameservers:
            raise dns.exception.DNSException("no-nameservers")
        # 其它异常 (Timeout/YXDOMAIN/...) 向上抛

    def _query_version_bind(self, host: str) -> str:
        """
        查 version.bind CHAOS TXT 记录 - 经典的 DNS 服务指纹.

        正常 DNS 服务器应拒绝; BIND 老版本/配置不当会返回版本字符串.
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [host]
            resolver.timeout = min(self.timeout, 3)
            resolver.lifetime = min(self.timeout, 3)
            answer = resolver.resolve("version.bind", "TXT", "CH")
            for r in answer:
                return r.to_text().strip('"')
        except Exception:
            return ""
        return ""

    def _do_xfr(self, domain: str, nameserver: str, timeout: float):
        """
        同步执行 AXFR.
        成功返回 dns.zone.Zone; 被拒绝/超时抛 DNSException.
        """
        xfr_iter = dns.query.xfr(
            nameserver, domain,
            timeout=timeout, lifetime=timeout + 5,
        )
        return dns.zone.from_xfr(xfr_iter)

    # ============================================================
    #                       生命周期
    # ============================================================

    async def close(self):
        self._closed = True
