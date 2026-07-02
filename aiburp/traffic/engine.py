"""
TrafficEngine - 统一流量引擎.

V4 "ALL-IN-TRAFFIC" 的对外入口. 取代 AsyncBurp 成为顶层流量调度器.

职责:
    1. 持有所有 ProtocolAdapter 实例 (协议路由表)
    2. send(): 根据 TrafficRequest.protocol 路由到对应 adapter
    3. smart_probe(): 协议自动识别 -> 探活 -> 指纹 -> 返回 Decision-like 报告
    4. probe() / fuzz(): 简化的协议无关入口

与 V3 关系:
    - 不替换 AsyncBurp, 而是把它包在 HttpAdapter 内
    - Decision / KB / OOB 复用 (engine 只产 TrafficResponse, 决策交给上层)
    - 现有代码用 AsyncBurp 不受影响, 新代码用 TrafficEngine
"""

import asyncio
import time
from typing import Dict, List, Optional, Tuple, Callable

from .base import (
    TrafficRequest,
    TrafficResponse,
    ProtocolAdapter,
    UnsupportedProtocol,
)
from .adapters import (
    HttpAdapter,
    TcpAdapter,
    DnsAdapter,
    RedisAdapter,
    DockerAdapter,
    KubeletAdapter,
    UdpAdapter,
    TlsAdapter,
    SnmpAdapter,
    MysqlAdapter,
    RmiAdapter,
    SmbAdapter,
    FtpAdapter,
    SshAdapter,
    WebSocketAdapter,
    detect_service_by_port,
    detect_service_by_banner,
    split_host_port,
)


# 默认扫描端口集 (红队高频高危端口, 按攻击价值排序)
DEFAULT_SCAN_PORTS = [
    # 高危未授权 RCE
    22,     # SSH (爆破)
    80,     # HTTP
    443,    # HTTPS
    445,    # SMB (EternalBlue)
    873,    # rsync
    1099,   # RMI (反序列化)
    1433,   # MSSQL
    1521,   # Oracle
    1883,   # MQTT
    2375,   # Docker
    3306,   # MySQL
    3389,   # RDP
    5432,   # PostgreSQL
    5900,   # VNC
    5985,   # WinRM
    6379,   # Redis
    8009,   # AJP
    8080,   # HTTP-alt
    8443,   # HTTPS-alt
    9000,   # Portainer/PHP-FPM
    9042,   # Cassandra
    9092,   # Kafka
    9200,   # Elasticsearch
    10250,  # Kubelet
    11211,  # Memcached
    27017,  # MongoDB
    50070,  # Hadoop NameNode
]


class TrafficEngine:
    """
    统一流量引擎.

    用法:
        async with TrafficEngine() as engine:
            # 1. 协议无关 probe (自动识别)
            resp = await engine.smart_probe("example.com:6379")
            print(resp.banner)  # "redis"

            # 2. 显式协议
            req = TrafficRequest(protocol="http", target="https://target.com/api",
                                 payload={"id": "1"})
            resp = await engine.send(req)

            # 3. 协议无关 fuzz
            results = await engine.fuzz("redis://10.0.0.1:6379",
                                         ["PING\\r\\n", "INFO\\r\\n"])
    """

    def __init__(
        self,
        adapters: Optional[List[ProtocolAdapter]] = None,
        http_kwargs: Optional[dict] = None,
        tcp_kwargs: Optional[dict] = None,
        dns_kwargs: Optional[dict] = None,
        redis_kwargs: Optional[dict] = None,
        docker_kwargs: Optional[dict] = None,
        kubelet_kwargs: Optional[dict] = None,
        udp_kwargs: Optional[dict] = None,
        tls_kwargs: Optional[dict] = None,
        snmp_kwargs: Optional[dict] = None,
        mysql_kwargs: Optional[dict] = None,
        rmi_kwargs: Optional[dict] = None,
        smb_kwargs: Optional[dict] = None,
        ftp_kwargs: Optional[dict] = None,
        ssh_kwargs: Optional[dict] = None,
        ws_kwargs: Optional[dict] = None,
        proxy_manager=None,
    ):
        """
        Args:
            adapters:      自定义适配器列表 (None = 用默认全套)
            http_kwargs:   HttpAdapter 参数
            tcp_kwargs:    TcpAdapter 参数
            dns_kwargs:    DnsAdapter 参数
            redis_kwargs:  RedisAdapter 参数
            docker_kwargs: DockerAdapter 参数
            kubelet_kwargs: KubeletAdapter 参数
            udp_kwargs:    UdpAdapter 参数
            tls_kwargs:    TlsAdapter 参数
            snmp_kwargs:   SnmpAdapter 参数
            mysql_kwargs:  MysqlAdapter 参数
            rmi_kwargs:    RmiAdapter 参数
            smb_kwargs:    SmbAdapter 参数
            ws_kwargs:     WebSocketAdapter 参数 (需 websockets 库)
        """
        self._adapters: Dict[str, ProtocolAdapter] = {}
        self._owned: List[ProtocolAdapter] = []
        self._closed = False
        self.proxy_manager = proxy_manager
        self._force_proxy: Optional[str] = None  # 强制代理 URL

        # 创建并注册 adapter
        if adapters is None:
            adapters = self._build_adapters(
                http_kwargs, tcp_kwargs, dns_kwargs,
                redis_kwargs, docker_kwargs, kubelet_kwargs,
                udp_kwargs, tls_kwargs, snmp_kwargs,
                mysql_kwargs, rmi_kwargs, smb_kwargs,
                ftp_kwargs, ssh_kwargs, ws_kwargs,
                proxy_manager,
            )
            self._owned = adapters

        for a in adapters:
            self.register(a)

    def _get_proxy_url(self) -> Optional[str]:
        """获取当前代理 URL (从 proxy_manager 或 _force_proxy)"""
        if self._force_proxy:
            return self._force_proxy
        if self.proxy_manager and self.proxy_manager.enabled:
            return self.proxy_manager.get_proxy()
        return None

    def set_proxy(self, proxy_url: Optional[str]):
        """
        强制设置全局代理 — 所有后续请求都走这个代理.

        设置后重建 HttpAdapter (httpx client 绑定代理).

        Args:
            proxy_url: 代理 URL (如 "socks5://127.0.0.1:7890")
                       None = 清除代理 (直连)
        """
        self._force_proxy = proxy_url

        # 重建 HttpAdapter (httpx client proxy 在创建时固定)
        if "http" in self._adapters:
            old_http = self._adapters["http"]
            http_kw = {
                "delay": 0,
                "timeout": old_http._burp.timeout if hasattr(old_http._burp, "timeout") else 30.0,
                "proxy": proxy_url,
            }
            new_http = HttpAdapter(**http_kw)
            self._adapters["http"] = new_http

    # ============================================================
    #                  adapter 创建 (构造函数调用)
    # ============================================================

    def _build_adapters(self, http_kwargs, tcp_kwargs, dns_kwargs,
                        redis_kwargs, docker_kwargs, kubelet_kwargs,
                        udp_kwargs, tls_kwargs, snmp_kwargs,
                        mysql_kwargs, rmi_kwargs, smb_kwargs,
                        ftp_kwargs, ssh_kwargs, ws_kwargs,
                        proxy_manager):
        """创建默认 adapter 列表 (含代理注入)"""
        proxy_url = None
        if proxy_manager and proxy_manager.enabled:
            proxy_url = proxy_manager.get_proxy()

        http_kw = dict(http_kwargs or {})
        tcp_kw = dict(tcp_kwargs or {})
        ssh_kw = dict(ssh_kwargs or {})
        redis_kw = dict(redis_kwargs or {})
        rmi_kw = dict(rmi_kwargs or {})
        tls_kw = dict(tls_kwargs or {})
        mysql_kw = dict(mysql_kwargs or {})
        if proxy_url:
            for kw in (http_kw, tcp_kw, ssh_kw, redis_kw, rmi_kw, tls_kw, mysql_kw):
                if "proxy" not in kw:
                    kw["proxy"] = proxy_url

        adapters = [
            HttpAdapter(**http_kw),
            TcpAdapter(**tcp_kw),
            DnsAdapter(**(dns_kwargs or {})),
            RedisAdapter(**redis_kw),
            DockerAdapter(**(docker_kwargs or {})),
            KubeletAdapter(**(kubelet_kwargs or {})),
            UdpAdapter(**(udp_kwargs or {})),
            TlsAdapter(**tls_kw),
            SnmpAdapter(**(snmp_kwargs or {})),
            MysqlAdapter(**mysql_kw),
            RmiAdapter(**rmi_kw),
            SmbAdapter(**(smb_kwargs or {})),
            FtpAdapter(**(ftp_kwargs or {})),
            SshAdapter(**ssh_kw),
        ]
        # Docker/Kubelet 内部用 HttpAdapter, 注入 proxy
        if proxy_url:
            for name in ("docker", "kubelet"):
                a = [x for x in adapters if x.protocol == name]
                if a and hasattr(a[0], "_http"):
                    # 重建内部 HttpAdapter 带 proxy
                    from .adapters import HttpAdapter as _HA
                    old_h = a[0]._http
                    a[0]._http = _HA(
                        delay=0,
                        timeout=getattr(old_h._burp, "timeout", 30.0),
                        proxy=proxy_url,
                    )
        if WebSocketAdapter is not None:
            adapters.append(WebSocketAdapter(**(ws_kwargs or {})))
        return adapters

    # ============================================================
    #                       注册管理
    # ============================================================

    def register(self, adapter: ProtocolAdapter):
        """注册协议适配器 (同名协议会被覆盖)"""
        self._adapters[adapter.protocol] = adapter

    def unregister(self, protocol: str):
        self._adapters.pop(protocol, None)

    def supports(self, protocol: str) -> bool:
        return protocol in self._adapters

    def adapter(self, protocol: str) -> ProtocolAdapter:
        """获取适配器 (不存在抛异常)"""
        a = self._adapters.get(protocol)
        if a is None:
            raise UnsupportedProtocol(protocol)
        return a

    @property
    def protocols(self) -> List[str]:
        return list(self._adapters.keys())

    # ============================================================
    #                       统一原语
    # ============================================================

    async def probe(self, target: str, protocol: str = "auto", **kw) -> TrafficResponse:
        """
        协议无关探活.

        Args:
            target:   URL 或 host:port
            protocol: "auto" = 自动识别; 否则指定协议名
        """
        if self._closed:
            return TrafficResponse(
                protocol="unknown", ok=False, status=0,
                target=target, error="engine-closed",
                anomalies=["engine 已 close, 不能再用"],
            )
        proto = await self._resolve_protocol(target, protocol)
        return await self.adapter(proto).probe(target, **kw)

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """
        根据 req.protocol 路由到对应 adapter.

        不支持的协议不抛异常 (与 probe/fuzz 一致), 返回 ok=False 的响应.
        """
        if self._closed:
            return TrafficResponse(
                protocol=req.protocol or "unknown", ok=False, status=0,
                target=req.target, payload=str(req.payload or ""),
                error="engine-closed",
                anomalies=["engine 已 close, 不能再用"],
            )
        adapter = self._adapters.get(req.protocol)
        if adapter is None:
            return TrafficResponse(
                protocol=req.protocol or "unknown",
                ok=False, status=0,
                target=req.target, payload=str(req.payload or ""),
                error=f"unsupported-protocol:{req.protocol}",
                anomalies=[f"supported:{','.join(self.protocols)}"],
            )
        return await adapter.send(req, **kw)

    async def fuzz(
        self,
        target: str,
        payloads: List[str],
        protocol: str = "auto",
        marker: str = "§",
        base: Optional[TrafficRequest] = None,
        **kw,
    ) -> List[TrafficResponse]:
        """协议无关 fuzz"""
        if self._closed:
            return [TrafficResponse(
                protocol="unknown", ok=False, status=0,
                target=target, error="engine-closed",
                anomalies=["engine 已 close, 不能再用"],
            ) for _ in payloads]
        proto = await self._resolve_protocol(target, protocol)
        return await self.adapter(proto).fuzz(
            target, payloads, marker=marker, base=base, **kw
        )

    # ============================================================
    #                    smart_probe (亮点)
    # ============================================================

    async def smart_probe(self, target: str, **kw) -> TrafficResponse:
        """
        智能探活: 自动识别协议 -> probe -> 附加语义标签与建议.

        比 probe() 多做的:
            - 显式解析协议 (可能尝试多种)
            - 在响应里追加 tags (HIGH-VALUE / AUTH / DB 等) 和建议信息
            - 对 http, 触发 IntentAnalyzer
            - 无效 target (既非 URL 也非 host:port) 直接报错, 不走 HTTP 兜底
        """
        if self._closed:
            return TrafficResponse(
                protocol="unknown", ok=False, status=0,
                target=target, error="engine-closed",
                anomalies=["engine 已 close, 不能再用"],
            )
        # target 基础校验: 必须有 scheme 或 host:port 结构
        t = target.strip()
        if "://" not in t and ":" not in t and "." not in t:
            return TrafficResponse(
                protocol="unknown", ok=False, status=0,
                target=target, error="invalid-target",
                anomalies=["target 既无 scheme 也无 host:port 也无域名点"],
            )

        proto = await self._resolve_protocol(target, "auto")
        adapter = self.adapter(proto)
        resp = await adapter.probe(target, **kw)

        # V4: 用 IntentAnalyzer 做多协议语义分析 (增强 AI 决策信息)
        # 协议无关地推断攻击价值, 替代原来硬编码的 HIGH-VALUE 列表
        try:
            from ..burp import IntentAnalyzer
            resp.tags = IntentAnalyzer.analyze_response(resp)
            # 把建议的下一步操作附到 anomalies (AI 可直接消费)
            steps = IntentAnalyzer.suggest_next_steps(resp.tags, proto)
            if steps:
                # 只把 action 名进 anomalies (desc 太长, 走 meta 通道)
                top_actions = [s["action"] for s in steps[:5]]
                for a in top_actions:
                    tag = f"next:{a}"
                    if tag not in resp.anomalies:
                        resp.anomalies.append(tag)
                # 完整建议存到 resp 的 next_steps 属性 (to_dict 会输出)
                setattr(resp, "next_steps", steps)
        except Exception:
            # IntentAnalyzer 失败不影响 probe 本身
            pass

        return resp

    async def check_unauth(self, target: str, protocol: str = "auto",
                           **kw) -> TrafficResponse:
        """
        统一未授权检测入口.

        对支持 check_unauth 的 adapter (redis/docker/kubelet), 自动调用.
        对不支持的, 返回提示.
        """
        proto = await self._resolve_protocol(target, protocol)
        adapter = self.adapter(proto)
        check_fn = getattr(adapter, "check_unauth", None)
        if check_fn is None:
            return TrafficResponse(
                protocol=proto, ok=False, status=0,
                target=target, error="no-check-unauth",
                anomalies=[f"{proto} adapter 不支持未授权检测, 用 probe()"],
            )
        return await check_fn(target, **kw)

    # ============================================================
    #             M6: 资产批量扫描
    # ============================================================

    async def scan_cidr(
        self,
        cidr: str,
        ports: Optional[List[int]] = None,
        concurrency: int = 50,
        timeout: Optional[float] = None,
        progress: Optional[Callable[[int, int], None]] = None,
        max_hosts: int = 65536,
        port_protocol_map: Optional[Dict[int, str]] = None,
    ) -> "ScanResult":
        """
        扫描一个 CIDR 网段的所有 host x port 组合.

        Args:
            cidr:        CIDR 表示法, 如 "10.0.0.0/24" / "192.168.1.0/28"
            ports:       端口列表 (None = 用默认高危端口集)
            concurrency: 全局并发上限 (避免打挂目标)
            timeout:     单次 probe 超时 (None = 用 adapter 默认)
            progress:    进度回调 (done, total)
            max_hosts:   最大 host 数上限 (默认 65536 = /16), 超过拒绝
                         防止 /8 (1600万) 等大网段卡死/OOM

        Returns:
            ScanResult, 含所有 AssetEntry + 统计
        """
        from .scan_result import ScanResult, AssetEntry
        import ipaddress

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            result = ScanResult(scan_target=cidr)
            result.entries.append(AssetEntry(
                host=cidr, port=0, error=f"invalid-cidr:{e}",
            ))
            return result

        # 计算 host 数 (考虑 IPv4/IPv6 差异)
        if network.version == 4:
            # IPv4: /31 /32 特殊 (hosts() 对 /32 返回空)
            if network.prefixlen >= 31:
                hosts = [str(network.network_address)]
            else:
                hosts = [str(ip) for ip in network.hosts()]
        else:
            # IPv6: 单 host (prefixlen >= 127) 或网段
            if network.prefixlen >= 127:
                hosts = [str(network.network_address)]
            else:
                # IPv6 大网段危险, 提前算 host 数限制
                num_hosts = network.num_addresses
                if num_hosts > max_hosts:
                    result = ScanResult(scan_target=cidr)
                    result.entries.append(AssetEntry(
                        host=cidr, port=0,
                        error=f"cidr-too-large:{num_hosts} hosts > {max_hosts}",
                    ))
                    return result
                hosts = [str(ip) for ip in network.hosts()]

        # 大网段保护 (IPv4)
        if len(hosts) > max_hosts:
            result = ScanResult(scan_target=cidr)
            result.entries.append(AssetEntry(
                host=cidr, port=0,
                error=f"cidr-too-large:{len(hosts)} hosts > {max_hosts}",
            ))
            return result

        if not hosts:
            hosts = [str(network.network_address)]

        port_list = ports if ports else DEFAULT_SCAN_PORTS
        return await self._scan_hosts_ports(
            hosts, port_list, cidr, concurrency, timeout, progress, port_protocol_map
        )

    async def scan_hosts(
        self,
        hosts: List[str],
        ports: Optional[List[int]] = None,
        concurrency: int = 50,
        timeout: Optional[float] = None,
        progress: Optional[Callable[[int, int], None]] = None,
        port_protocol_map: Optional[Dict[int, str]] = None,
    ) -> "ScanResult":
        """
        扫描 host 列表 x 端口列表.

        Args:
            hosts:             主机列表 ["10.0.0.1", "10.0.0.2", ...]
            ports:             端口列表 (None = 默认高危端口集)
            concurrency:       并发上限
            timeout:           单次 probe 超时
            progress:          进度回调
            port_protocol_map: 手动指定端口→协议映射 (覆盖端口表)
                              例: {6389: "redis", 4450: "smb", 3316: "mysql"}
                              用于 Docker 端口映射等非标准端口场景

        Returns:
            ScanResult
        """
        port_list = ports if ports else DEFAULT_SCAN_PORTS
        target_desc = f"{len(hosts)} hosts x {len(port_list)} ports"
        return await self._scan_hosts_ports(
            hosts, port_list, target_desc, concurrency, timeout, progress, port_protocol_map
        )

    async def _scan_hosts_ports(
        self,
        hosts: List[str],
        ports: List[int],
        scan_target: str,
        concurrency: int,
        timeout: Optional[float],
        progress: Optional[Callable[[int, int], None]],
        port_protocol_map: Optional[Dict[int, str]] = None,
    ) -> "ScanResult":
        """核心扫描逻辑: 笛卡尔积 host x port, 并发 probe"""
        from .scan_result import ScanResult, AssetEntry

        result = ScanResult(
            scan_target=scan_target,
            concurrency=concurrency,
        )
        result.start_time = time.monotonic()

        # close 后不扫描, 返回错误 (与 send/probe/fuzz 的 _closed 保护一致)
        if self._closed:
            result.end_time = time.monotonic()
            result.entries.append(AssetEntry(
                host=scan_target, port=0,
                error="engine-closed",
                anomalies=["engine 已 close, 不能再扫描"],
            ))
            return result

        # 构造所有 (host, port) 组合
        targets = [(h, p) for h in hosts for p in ports]
        result.total_probes = len(targets)
        sem = asyncio.Semaphore(concurrency)
        done_count = 0

        async def probe_one(host: str, port: int) -> AssetEntry:
            nonlocal done_count
            async with sem:
                target = f"{host}:{port}"
                # 协议路由优先级:
                # 1. port_protocol_map (用户手动指定, 最高优先)
                # 2. 端口表 (detect_service_by_port)
                # 3. 兜底 tcp
                proto = "tcp"
                if port_protocol_map and port in port_protocol_map:
                    user_proto = port_protocol_map[port]
                    if user_proto in self._adapters:
                        proto = user_proto
                else:
                    port_hint = detect_service_by_port(port)
                    if port_hint:
                        if port_hint[1] in self._adapters:
                            proto = port_hint[1]
                        elif port_hint[0] in self._adapters:
                            proto = port_hint[0]

                try:
                    kw = {"timeout": timeout} if timeout else {}
                    resp = await self.adapter(proto).probe(target, **kw)
                    # 跑 IntentAnalyzer (高危标注)
                    try:
                        from ..burp import IntentAnalyzer
                        resp.tags = IntentAnalyzer.analyze_response(resp)
                        steps = IntentAnalyzer.suggest_next_steps(resp.tags, proto)
                        if steps:
                            setattr(resp, "next_steps", steps)
                    except Exception:
                        pass
                    entry = AssetEntry.from_response(host, port, proto, resp)
                except Exception as e:
                    entry = AssetEntry(
                        host=host, port=port, protocol=proto,
                        error=f"{type(e).__name__}:{e}",
                    )
                finally:
                    done_count += 1
                    if progress:
                        try:
                            progress(done_count, result.total_probes)
                        except Exception:
                            pass
                return entry

        # 并发执行所有 probe
        tasks = [probe_one(h, p) for h, p in targets]
        entries = await asyncio.gather(*tasks)

        for e in entries:
            result.add(e)

        result.end_time = time.monotonic()
        return result

    # ============================================================
    #                  协议自动识别
    # ============================================================

    async def _resolve_protocol(self, target: str, hint: str) -> str:
        """
        把 target 解析为 UPM 协议名.

        优先级:
            1. 显式 hint (非 "auto") 直接用
            2. target 里有 scheme:// 前缀 (http/redis/...) 直接用
            3. target 是 host:port, 用端口表查
            4. 兜底 http
        """
        if hint and hint != "auto":
            if hint not in self._adapters:
                raise UnsupportedProtocol(hint)
            return hint

        s = target.strip().lower()

        # 1. scheme:// 前缀
        if "://" in s:
            scheme = s.split("://", 1)[0]
            # http(s) 复用 http adapter
            if scheme in ("http", "https"):
                return "http"
            # ws(s) 用 ws adapter (若已注册)
            if scheme in ("ws", "wss") and "ws" in self._adapters:
                return "ws"
            # 已注册的同名 adapter 直接用
            if scheme in self._adapters:
                return scheme
            # scheme 是已知服务但还没专门 adapter -> 按服务族归类
            from .adapters.fingerprints import KNOWN_PORT_SERVICE
            all_services = {svc for proto, svc in KNOWN_PORT_SERVICE.values()}
            if scheme in all_services:
                # 找该服务对应的 upm 协议
                for proto, svc in KNOWN_PORT_SERVICE.values():
                    if svc == scheme and proto in self._adapters:
                        return proto
                return "tcp"

        # 2. 端口表 - 端口对应的 service 名若与 adapter 同名, 直接用
        host, port = split_host_port(s)
        if port:
            hit = detect_service_by_port(port)
            if hit:
                upm_proto, service = hit
                # 优先: service 名与 adapter 同名 (redis/docker/kubelet)
                if service in self._adapters:
                    return service
                # 其次: upm_proto (http/tcp/dns) 有 adapter
                if upm_proto in self._adapters:
                    return upm_proto
                return "tcp"

        # 3. 兜底
        return "http"

    # ============================================================
    #                       生命周期
    # ============================================================

    async def close(self):
        """只关闭引擎自建的 adapter; 外部注入的由外部负责"""
        if self._closed:
            return  # 幂等
        self._closed = True
        for a in self._owned:
            try:
                await a.close()
            except Exception:
                pass
        self._adapters.clear()
        self._owned.clear()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
