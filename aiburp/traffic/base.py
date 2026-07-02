"""
统一协议模型 (Universal Protocol Model, UPM) - 数据结构与契约

定义:
    TrafficRequest  - 任意协议的统一请求抽象
    TrafficResponse - 任意协议的统一响应抽象 (是 aiburp.Response 的超集)
    ProtocolAdapter - 协议适配器基类 (每个协议实现一个)

设计决策:
    - TrafficResponse 是 HTTP Response 的超集: HTTP 适配器返回的字段
      (status/body/headers/url/method) 与现有 aiburp.Response 完全一致,
      保证旧代码零改动.
    - raw: bytes 保留原始字节流, 协议无关; text 是解码后的字符串.
    - banner 字段独立: TCP banner / TLS 证书 / DNS 版本 / 空(HTTP).
    - 异常标记 (error/blocked/reflects/anomalies) 统一, 供 Decision 复用.
    - ProtocolAdapter 只强制 probe + send, fuzz 默认基于 send 实现,
      可被子类覆盖以做协议级优化.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ============================================================
#                       异常定义
# ============================================================

class ProtocolError(Exception):
    """协议层通用异常"""
    pass


class UnsupportedProtocol(ProtocolError):
    """不支持的协议"""
    def __init__(self, protocol: str):
        super().__init__(f"Unsupported protocol: {protocol}")
        self.protocol = protocol


class ProtocolTimeout(ProtocolError):
    """协议交互超时"""
    pass


# ============================================================
#                    统一数据结构
# ============================================================

@dataclass
class TrafficRequest:
    """
    统一请求抽象 - 任意协议.

    Attributes:
        protocol: 协议标识 ("http" | "https" | "tcp" | "udp" | "dns" | "ws")
        target:   目标. HTTP 是完整 URL; 其它协议是 "host:port".
        payload:  注入载荷. 协议自定义类型:
                    - http: dict (params) / str (body)
                    - tcp/udp: bytes / str
                    - dns: str (query name)
        headers:  元数据 (协议自定义语义, 如 HTTP headers / TCP 行分隔参数)
        marker:   注入点标识, 用于 fuzz. 为空表示整体注入.
        meta:     协议私有字段扩展位 (如 DNS rdtype, TLS SNI).
    """
    protocol: str
    target: str
    payload: Any = None
    headers: Dict[str, Any] = field(default_factory=dict)
    marker: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)

    def with_payload(self, payload: Any) -> "TrafficRequest":
        """链式: 替换 payload, 返回新请求 (用于 fuzz)"""
        return TrafficRequest(
            protocol=self.protocol,
            target=self.target,
            payload=payload,
            headers=dict(self.headers),
            marker=self.marker,
            meta=dict(self.meta),
        )


@dataclass
class TrafficResponse:
    """
    统一响应抽象 - 任意协议.

    是 aiburp.Response (HTTP) 的超集:
      - HTTP 适配器填 status/body/headers/url/method
      - TCP/UDP 填 raw/banner
      - DNS 填 raw (DNS 报文) / banner (version) / status (rcode)

    统一异常标记 (error/blocked/reflects/anomalies) 让 Decision 层无需
    关心底层协议, 直接消费统一字段做决策.
    """
    protocol: str = ""

    # 基础结果
    ok: bool = True
    status: int = 0              # HTTP code / DNS rcode / TCP 约定: 0=未知
    time_ms: float = 0.0

    # 内容 (保真)
    raw: bytes = b""             # 原始字节流 (协议无关)
    text: str = ""               # 解码后文本
    banner: str = ""             # 协议指纹 (TCP banner / TLS CN / DNS ver)

    # HTTP 专用 (向后兼容 aiburp.Response)
    length: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    url: str = ""
    method: str = ""
    target: str = ""     # 非 HTTP 协议的 "host:port" 溯源

    # 统一异常标记 (供 Decision / IntentAnalyzer 复用)
    error: str = ""              # 错误类型 (mysql/oracle/...)
    blocked: bool = False        # WAF/ACL 拦截
    reflects: bool = False       # payload 是否回显
    anomalies: List[str] = field(default_factory=list)

    # 注入元数据
    payload: str = ""            # 触发本次响应的 payload (fuzz 时填)
    tags: List[str] = field(default_factory=list)  # 语义标签 (AUTH/DB/...)

    # 兼容 aiburp.Response 的属性
    body: str = ""               # 别名 -> text

    def __post_init__(self):
        # body <-> text 别名: HTTP 旧代码用 .body, 新代码用 .text
        # 三种合法用法:
        #   1. 只给 text  -> body 同步
        #   2. 只给 body  -> text 同步
        #   3. 都给且相等 -> 无操作
        # 都给但不等 -> 静默 bug, 这里告警 (不抛错避免破坏调用方), 以 text 为准
        if self.text and not self.body:
            self.body = self.text
        elif self.body and not self.text:
            self.text = self.body
        elif self.text and self.body and self.text != self.body:
            import warnings
            warnings.warn(
                f"TrafficResponse text/body 不一致: text={self.text[:50]!r} "
                f"vs body={self.body[:50]!r}; 以 text 为准",
                stacklevel=2,
            )
            self.body = self.text

    def __str__(self) -> str:
        flags = []
        if self.error:     flags.append(f"ERR:{self.error}")
        if self.blocked:   flags.append("BLOCKED")
        if self.reflects:  flags.append("REFLECTS")
        if self.banner:    flags.append(f"BANNER:{self.banner[:20]}")
        if self.tags:      flags.append(f"TAGS:{','.join(self.tags[:2])}")
        flag_str = f" [{','.join(flags)}]" if flags else ""
        return f"[{self.protocol}:{self.status}] {self.length}b {self.time_ms:.0f}ms{flag_str}"

    @property
    def is_interesting(self) -> bool:
        """是否值得关注 (与 aiburp.Response 语义一致)"""
        return (bool(self.error)
                or self.reflects
                or self.blocked
                or len(self.anomalies) > 0
                or bool(self.banner))

    def to_dict(self, include_raw: bool = True, raw_max: int = 4096) -> Dict[str, Any]:
        """
        转为 JSON 友好的 dict (供 ide_cli / Agent 模式输出).

        bytes 字段 (raw) 用 base64 编码 + "b64:" 前缀, 避免标准 json.dumps 崩.
        二进制过大时按 raw_max 截断 (字节), 防止 OOM.

        Args:
            include_raw: 是否包含 raw 字段 (AI 通常不需要原始字节)
            raw_max:     raw 保留的最大字节数
        """
        d: Dict[str, Any] = {
            "protocol": self.protocol,
            "ok": self.ok,
            "status": self.status,
            "time_ms": round(self.time_ms, 1),
            "length": self.length,
            "text": self.text,
            "banner": self.banner,
            "url": self.url,
            "method": self.method,
            "target": self.target,
            "error": self.error,
            "blocked": self.blocked,
            "reflects": self.reflects,
            "anomalies": list(self.anomalies),
            "tags": list(self.tags),
            "payload": self.payload,
            "is_interesting": self.is_interesting,
        }
        # next_steps: IntentAnalyzer 建议的攻击操作 (smart_probe 后才有)
        # 用 getattr 安全读, 没分析过的响应返回空列表
        next_steps = getattr(self, "next_steps", None) or []
        d["next_steps"] = list(next_steps)
        if include_raw and self.raw:
            raw = self.raw[:raw_max]
            try:
                import base64
                d["raw_b64"] = "b64:" + base64.b64encode(raw).decode("ascii")
                d["raw_truncated"] = len(self.raw) > raw_max
            except Exception:
                d["raw_b64"] = ""
        return d

    def to_json(self, **kw) -> str:
        """转为 JSON 字符串 (用 to_dict, 保证可序列化)"""
        import json
        return json.dumps(self.to_dict(**kw), ensure_ascii=False)


# ============================================================
#                  协议适配器基类
# ============================================================

class ProtocolAdapter(ABC):
    """
    协议适配器基类.

    每个具体协议 (HTTP/TCP/UDP/DNS/...) 实现一个子类, 注册到 TrafficEngine.

    5 个原语映射:
        Probe   -> probe()
        Send    -> send()
        Reflect -> send() 返回的 TrafficResponse.text/raw/banner
        OOB     -> 由 engine 层注入 InteractshClient, adapter 不感知
        State   -> 子类按需 (如 TLS session 复用, TCP keepalive)
    """

    protocol: str = "base"
    description: str = ""

    def __init__(self, timeout: float = 10.0, concurrency: int = 10):
        self.timeout = timeout
        self._concurrency = concurrency

    # -------- 必须实现的两个原语 --------

    @abstractmethod
    async def probe(self, target: str, **kw) -> TrafficResponse:
        """
        探活 + 指纹.
        - HTTP: GET / 看状态码 + Server header
        - TCP:  connect + 读 banner
        - DNS:  SOA/NS 查询看版本
        """
        raise NotImplementedError

    @abstractmethod
    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """发送请求, 返回响应"""
        raise NotImplementedError

    # -------- 通用 fuzz (默认实现, 子类可覆盖) --------

    async def fuzz(
        self,
        target: str,
        payloads: List[str],
        marker: str = "§",
        base: Optional[TrafficRequest] = None,
        **kw,
    ) -> List[TrafficResponse]:
        """
        通用 Fuzz - 对每个 payload 替换 marker 后 send.

        Args:
            target:   目标 (URL 或 host:port)
            payloads: payload 列表
            marker:   在 target / base.payload 中替换的占位符
            base:     基础请求模板 (可选). 若提供, 在其 payload 中替换 marker;
                      否则在 target 中替换.

        默认实现串行; 子类可用 asyncio.gather 做并发优化.
        """
        results = []
        for p in payloads:
            if base:
                req = self._inject_into_request(base, p, marker)
            else:
                req = TrafficRequest(
                    protocol=self.protocol,
                    target=target.replace(marker, str(p)),
                    payload=str(p),
                )
            resp = await self.send(req, **kw)
            resp.payload = str(p)
            results.append(resp)
        return results

    @staticmethod
    def _inject_into_request(
        base: TrafficRequest, payload: Any, marker: str
    ) -> TrafficRequest:
        """
        在基础请求中替换 marker (target / payload 两处都换).

        payload 参数类型 (保持原样, 不强转):
            - str:   字符串替换
            - bytes: 字节替换 (保持 bytes 类型, 不被 repr 化)
            - None:  payload 直接用传入的值

        支持的 base.payload 类型:
            - str:   字符串替换 (TCP/DNS 常用)
            - bytes: 字节替换 (TCP 二进制协议)
            - None:  payload 直接用传入的值

        不支持的类型 (会抛 TypeError):
            - dict / list: 结构化 payload 的 marker 注入语义不明确,
              这类场景应由具体 adapter (如 HttpAdapter) 自行处理,
              而不是走通用 fuzz 路径.
        """
        # 把 payload 转成与替换目标匹配的字符串/字节形式 (不改变原 payload 类型)
        if isinstance(payload, (bytes, bytearray)):
            payload_str = bytes(payload).decode("utf-8", "replace")
            payload_bytes = bytes(payload)
        else:
            payload_str = str(payload)
            payload_bytes = payload_str.encode("utf-8")

        new_target = (base.target.replace(marker, payload_str)
                      if marker in base.target else base.target)

        # 默认: payload 直接用传入值 (保持原类型)
        new_payload: Any = payload

        if base.payload is None:
            pass  # 用默认值
        elif isinstance(base.payload, str):
            if marker in base.payload:
                new_payload = base.payload.replace(marker, payload_str)
            # marker 不在 payload 里: 保持原 payload 不变 (避免误覆盖)
        elif isinstance(base.payload, (bytes, bytearray)):
            marker_b = marker.encode("utf-8")
            if marker_b in base.payload:
                new_payload = bytes(base.payload).replace(marker_b, payload_bytes)
            # marker 不在: 保持原值
        else:
            # dict / list / 其它结构化类型 - marker 注入语义不明, 拒绝
            raise TypeError(
                f"_inject_into_request 不支持 {type(base.payload).__name__} 类型 payload; "
                f"结构化 payload 的 fuzz 请用具体 adapter 的 fuzz 方法"
            )

        return TrafficRequest(
            protocol=base.protocol,
            target=new_target,
            payload=new_payload,
            headers=dict(base.headers),
            marker=base.marker or marker,
            meta=dict(base.meta),
        )

    # -------- 生命周期 --------

    async def close(self):
        """释放资源 (连接池等). 默认空实现."""
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
