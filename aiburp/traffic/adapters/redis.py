"""
Redis 协议适配器 - 高危未授权服务检测.

Redis 未授权访问 (默认 6379 无密码) 是内网/云上最常见的 RCE 入口之一:
    - 写 SSH authorized_keys 直接登录
    - 写 cron 任务反弹 shell
    - 主从复制 RCE (SLAVEOF + module load)
    - 写 webshell 到 web 目录

本 adapter 继承 TcpAdapter, 在其之上加 RESP (REdis Serialization Protocol) 感知:
    - probe():    发 PING, 确认是 Redis + 是否需要认证
    - send():     发任意 Redis 命令
    - check_unauth(): 一键未授权检测 (PING + INFO)

设计:
    - 继承 TcpAdapter (Redis 本质是 TCP + RESP 文本协议)
    - RESP 简单字符串: +OK\\r\\n  错误: -ERR\\r\\n  批量: $N\\r\\n...\\r\\n
    - 用 TcpAdapter._connect_and_read 复用连接逻辑
"""

import asyncio
from typing import Optional

from ..base import TrafficRequest, TrafficResponse
from .tcp import TcpAdapter
from .fingerprints import split_host_port


class RedisAdapter(TcpAdapter):
    """
    Redis 协议适配器.

    用法:
        async with RedisAdapter() as r:
            resp = await r.probe("10.0.0.1:6379")        # 探活
            resp = await r.check_unauth("10.0.0.1:6379") # 未授权检测

            # 发任意命令
            req = TrafficRequest(protocol="redis", target="10.0.0.1:6379",
                                 payload="CONFIG GET dir")
            resp = await r.send(req)
    """

    protocol = "redis"
    description = "Redis adapter (RESP protocol, unauth detection)"

    DEFAULT_PORT = 6379

    # Redis 命令需要 CRLF 结尾; _coerce_payload 已处理 \\r\\n 字面量转真换行
    # 但 Redis 命令是单行, 我们在 send 时统一补 CRLF

    def __init__(self, timeout: float = 3.0, concurrency: int = 10,
                 read_window: float = 2.0, proxy: Optional[str] = None):
        super().__init__(timeout=timeout, concurrency=concurrency,
                         read_window=read_window, proxy=proxy)

    # ============================================================
    #                         probe
    # ============================================================

    async def probe(self, target: str, **kw) -> TrafficResponse:
        """
        探活: 发 PING.
        - +PONG           -> Redis 在线, 无需认证
        - NOAUTH 错误     -> Redis 在线, 需要认证 (安全配置)
        - 无响应/拒绝      -> 非 Redis 或不可达
        """
        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT

        closed = self._check_closed(target)
        if closed:
            return closed

        try:
            raw, _banner, elapsed = await self._connect_and_read(
                host, port,
                send=b"PING\r\n",
                timeout=kw.get("timeout", self.timeout),
                max_rounds=2,
            )
        except asyncio.TimeoutError:
            return TrafficResponse(
                protocol="redis", ok=False, status=0,
                target=target, error="timeout",
                time_ms=self.timeout * 1000,
            )
        except OSError as e:
            return TrafficResponse(
                protocol="redis", ok=False, status=0,
                target=target, error=type(e).__name__,
            )

        text = self._safe_decode(raw)
        tags = []
        anomalies = []
        banner = ""

        # RESP 解析
        if "+PONG" in text:
            ok = True
            status = 1
            banner = "redis"
            tags = ["REDIS", "UNAUTH-OK"]  # PONG 回来 = 无认证
            anomalies.append("ping-success")
            # 标记高危: 无认证的 Redis 是 RCE 入口
            if "NOAUTH" not in text:
                tags.append("HIGH-VALUE")
                tags.append("UNAUTH-CHECK")
        elif "NOAUTH" in text:
            ok = True
            status = 1
            banner = "redis(auth-required)"
            tags = ["REDIS", "AUTH-REQUIRED"]
            anomalies.append("auth-required")
        elif text and text[:1] in "+-$*:":
            # 有响应且是 RESP 格式 (以 +/-/$/*/://开头) 但不是 PONG
            # 可能是 Redis 但命令不兼容, 或需认证
            ok = True
            status = 1
            banner = "redis?"
            tags = ["REDIS"]
            anomalies.append("resp-but-not-pong")
        else:
            # 非 Redis 响应 (HTTP/SSH/其它) - 不标 REDIS tag, 避免误判
            ok = False
            status = 0
            anomalies.append("not-redis-or-no-response")

        return TrafficResponse(
            protocol="redis",
            ok=ok,
            status=status,
            raw=raw,
            text=text,
            banner=banner,
            time_ms=elapsed,
            target=target,
            tags=tags,
            anomalies=anomalies,
        )

    # ============================================================
    #                          send
    # ============================================================

    async def send(self, req: TrafficRequest, **kw) -> TrafficResponse:
        """
        发送 Redis 命令.

        req.payload: Redis 命令字符串 (如 "GET key" / "CONFIG GET dir").
                     自动补 \\r\\n. 支持 RESP 数组形式 (list).
        """
        host, port = split_host_port(req.target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT

        closed = self._check_closed(req.target)
        if closed:
            return closed

        # 命令编码为 RESP
        cmd_bytes = self._encode_command(req.payload)

        try:
            raw, _banner, elapsed = await self._connect_and_read(
                host, port,
                send=cmd_bytes,
                timeout=kw.get("timeout", self.timeout),
                max_rounds=req.meta.get("read_rounds", 5),
            )
        except asyncio.TimeoutError:
            return TrafficResponse(
                protocol="redis", ok=False, status=0,
                target=req.target, payload=self._payload_str(req.payload),
                error="timeout", time_ms=self.timeout * 1000,
            )
        except OSError as e:
            return TrafficResponse(
                protocol="redis", ok=False, status=0,
                target=req.target, payload=self._payload_str(req.payload),
                error=type(e).__name__,
            )

        text = self._safe_decode(raw)
        reflects = bool(req.payload and str(req.payload).encode() in raw)

        anomalies = []
        if "-NOAUTH" in text or "NOAUTH" in text:
            anomalies.append("auth-required")
        if "+OK" in text or "$" in text[:3]:
            anomalies.append("command-accepted")

        return TrafficResponse(
            protocol="redis",
            ok=True,
            status=1,
            raw=raw,
            text=text,
            length=len(raw),
            time_ms=elapsed,
            target=req.target,
            payload=self._payload_str(req.payload),
            reflects=reflects,
            anomalies=anomalies,
        )

    # ============================================================
    #                  check_unauth (一键未授权检测)
    # ============================================================

    async def check_unauth(self, target: str, timeout: Optional[float] = None
                           ) -> TrafficResponse:
        """
        一键 Redis 未授权检测.

        流程:
            1. PING       -> 确认是 Redis
            2. INFO       -> 拿版本 + 配置 (无授权才能成功)
            3. CONFIG GET dir -> 探测写权限 (进一步 RCE 可能)

        Returns:
            TrafficResponse:
                ok=True + tags 含 UNAUTH-CONFIRMED = 确认未授权 (高危)
                ok=True + tags 含 AUTH-REQUIRED   = 需要认证 (安全)
                ok=False                          = 非 Redis 或不可达
        """
        host, port = split_host_port(target, self.DEFAULT_PORT)
        if port == 0:
            port = self.DEFAULT_PORT
        t = timeout or self.timeout

        # 1. PING
        ping_resp = await self.probe(target, timeout=t)
        if not ping_resp.ok:
            return ping_resp  # 不可达, 直接返回

        if "AUTH-REQUIRED" in ping_resp.tags:
            # 需要认证 - 这是安全状态
            return TrafficResponse(
                protocol="redis", ok=True, status=1,
                target=target, banner="redis(auth-required)",
                tags=["REDIS", "AUTH-REQUIRED"],
                anomalies=["auth-required", "secure-config"],
                time_ms=ping_resp.time_ms,
            )

        # 2. INFO (确认未授权 + 拿版本)
        info_resp = await self.send(
            TrafficRequest(protocol="redis", target=target, payload="INFO server"),
            timeout=t,
        )

        tags = ["REDIS", "UNAUTH-CONFIRMED", "HIGH-VALUE"]
        anomalies = ["unauth-access", "ping-success"]
        version = ""

        if info_resp.ok and "redis_version" in info_resp.text:
            # 提取版本
            for line in info_resp.text.split("\n"):
                if line.startswith("redis_version:"):
                    version = line.split(":", 1)[1].strip()
                    break
            anomalies.append(f"version:{version}")
            anomalies.append("info-leaked")

        # 3. (可选) CONFIG GET dir - 探写权限, 标记 RCE 可能
        # CONFIG 命令能执行 (不返回 -ERR permission denied) = 可读配置 = 可写 = RCE 可能
        dir_resp = await self.send(
            TrafficRequest(protocol="redis", target=target, payload="CONFIG GET dir"),
            timeout=t,
        )
        if dir_resp.ok:
            dir_text = dir_resp.text.lower()
            # CONFIG 可执行的特征: RESP 响应不报错 (-ERR), 且有内容
            # -ERR 说明权限拒绝; 否则 (含 *N/$len 格式或 dir 字面量) 说明可读
            config_readable = (
                "-err" not in dir_text
                and "nopass" not in dir_text
                and ("dir" in dir_text or dir_text.strip().startswith("*"))
            )
            if config_readable:
                anomalies.append("config-readable")
                anomalies.append("rce-possible")  # 能读配置 = 能写 = RCE 可能

        banner = f"redis/{version}" if version else "redis"

        return TrafficResponse(
            protocol="redis",
            ok=True,
            status=1,
            text=info_resp.text[:2000],
            raw=info_resp.raw,
            banner=banner,
            time_ms=ping_resp.time_ms + info_resp.time_ms + dir_resp.time_ms,
            target=target,
            tags=tags,
            anomalies=anomalies,
        )

    # ============================================================
    #                  RESP 编码工具
    # ============================================================

    @staticmethod
    def _encode_command(cmd) -> bytes:
        """
        把 Redis 命令编码为 RESP 字节.

        支持两种输入:
            - str:  "GET key"  -> RESP 数组 *2\r\n$3\r\nGET\r\n$3\r\nkey\r\n
            - list: ["GET", "key"] -> 同上
            - bytes: 直接返回 (假定调用方已编码)

        安全: 拒绝参数内含 \\r 或 \\n 的命令 - RESP 按 CRLF 分帧,
        参数含换行会导致协议走私 (Redis 命令注入, 如 FLUSHALL).
        红队工具自己不能有注入漏洞.
        """
        if cmd is None:
            return b""
        if isinstance(cmd, (bytes, bytearray)):
            # bytes 模式假定调用方已编码, 但仍检查 CRLF 注入
            raw = bytes(cmd)
            # 已编码的 RESP (以 * 开头) 直接返回; 否则当原始命令处理
            if raw.startswith(b"*"):
                return raw if raw.endswith(b"\r\n") else raw + b"\r\n"
            # 当原始命令字节处理, 走下面的 split 逻辑
            cmd = raw.decode("utf-8", "replace")

        # 统一成 list[str]
        if isinstance(cmd, str):
            parts = cmd.split()
        else:
            parts = [str(x) for x in cmd]

        if not parts:
            return b""

        # 安全检查: 拒绝参数内含 CR/LF (RESP 命令注入防护)
        for p in parts:
            if "\r" in p or "\n" in p:
                raise ValueError(
                    f"Redis 命令参数含换行符 (CR/LF), 拒绝编码以防 RESP 协议走私: {p!r}"
                )

        # RESP 数组编码: *N\r\n$len\r\narg\r\n...
        out = [f"*{len(parts)}".encode()]
        for p in parts:
            pb = p.encode("utf-8")
            out.append(f"${len(pb)}".encode())
            out.append(pb)
        return b"\r\n".join(out) + b"\r\n"
