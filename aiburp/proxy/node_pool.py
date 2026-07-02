"""
DOLA 节点 IP + 积分池

设计参考: repo/backend/core/account_pool/pool_core.go
- 每个节点绑定一个常驻 MiniClash 实例 (固定端口, 不再 switch_node)
- 跟踪每个 IP 的当日积分余额 (6/天/IP)
- 并发安全的 acquire/release (threading.Lock)
- 积分耗尽自动标记 cooldown, 到时间自动重置

核心区别 vs account_pool:
- account_pool 池化的是 token (账号), 这里池化的是 IP (节点)
- 积分按 IP 计 (不是按浏览器实例), 一个 IP 一天 6 积分
"""
import os
import sys
import time
import json
import threading
from typing import Optional, List, Dict, Any

# 支持 proxy/ 子目录和根目录两种调用方式
_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from .mini_clash import MiniClash

# 内置配置 (替代原 qwen2API 的 config 模块)
class _Config:
    CREDITS_PER_DAY = 6
    CREDITS_RESET_PERIOD = 86400  # 24h
    MAX_INFLIGHT_PER_NODE = 2
    POOL_SIZE = 8

config = _Config()


class NodeState:
    """单个节点的运行时状态"""
    def __init__(self, name: str, proxy_config: dict):
        self.name = name
        self.proxy_config = proxy_config          # yaml 里的 proxy 配置
        self.mc: Optional[MiniClash] = None       # 常驻 MiniClash 实例
        self.proxy_url: str = ""                   # http://127.0.0.1:{port}
        self.credits_remaining: int = config.CREDITS_PER_DAY
        self.credits_reset_at: float = time.time() + config.CREDITS_RESET_PERIOD
        self.inflight: int = 0                     # 当前在跑的任务数
        self.rate_limited_until: float = 0         # 风控冷却时间戳
        self.consecutive_failures: int = 0
        self.last_used: float = 0
        self.total_generated: int = 0              # 累计成功生成数
        self.total_submitted: int = 0              # 累计提交数 (含失败)
        self.status: str = "idle"                  # idle/starting/in_use/cooldown/error

    def available(self) -> bool:
        """是否可用 (有积分 + 未冷却 + 并发未满)
        关键: 积分在提交时预扣 (2026-06-22 风控实测)
        DOLA 超过 6 次/天后 conv_id 仍成功但视频永不生成
        """
        now = time.time()
        if now < self.rate_limited_until:
            return False
        if self.inflight >= config.MAX_INFLIGHT_PER_NODE:
            return False
        # 检查积分重置
        if now > self.credits_reset_at:
            self.credits_remaining = config.CREDITS_PER_DAY
            self.credits_reset_at = now + config.CREDITS_RESET_PERIOD
        return self.credits_remaining > 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.proxy_config.get("type", ""),
            "server": self.proxy_config.get("server", ""),
            "port": self.proxy_config.get("port", 0),
            "proxy_url": self.proxy_url,
            "status": self.status,
            "credits_remaining": self.credits_remaining,
            "credits_reset_at": self.credits_reset_at,
            "inflight": self.inflight,
            "rate_limited_until": self.rate_limited_until,
            "consecutive_failures": self.consecutive_failures,
            "last_used": self.last_used,
            "total_generated": self.total_generated,
            "total_submitted": self.total_submitted,
        }


class NodePool:
    """
    节点池: 管理所有 CAPABLE 节点的 MiniClash 实例 + 积分 + 并发

    生命周期:
      - start(): 从 yaml 加载节点, 为每个节点起 MiniClash (按需启动, 非 eager)
      - acquire(): 租一个可用节点 (扣积分在 release 时做)
      - release(node, success): 归还, 成功则扣积分, 失败则记 failure
      - stop(): 关闭所有 MiniClash
    """
    def __init__(self, yaml_path: str = None):
        self.yaml_path = yaml_path or config.CAPABLE_YAML
        self.nodes: List[NodeState] = []
        self._lock = threading.Lock()
        self._started = False

    def load_nodes(self) -> int:
        """从 yaml 加载节点配置 (不启动 MiniClash)"""
        import yaml
        if not os.path.isfile(self.yaml_path):
            raise FileNotFoundError(f"节点 yaml 不存在: {self.yaml_path}")
        with open(self.yaml_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
        proxies = cfg.get("proxies", []) or []
        self.nodes = [NodeState(p.get("name", f"node_{i}"), p)
                      for i, p in enumerate(proxies)]
        return len(self.nodes)

    def _ensure_mini_clash(self, node: NodeState) -> bool:
        """为节点启动常驻 MiniClash (惰性启动, 首次用时才起)

        关键: 用完整 dola_capable.yaml 作为配置, 让 mihomo 自己解析所有字段
        (自己拼单节点 yaml 会因 clash-meta 专有字段解析失败)
        每个 MiniClash 实例独立端口 + switch 到自己的节点 = 完全隔离
        """
        if node.mc and node.proxy_url:
            return True

        node.status = "starting"
        # 直接用原始 yaml (含全部节点), mihomo 能正确解析所有字段
        # 每个 MiniClash 实例用 auto_port 独立端口, 互不冲突
        mc = MiniClash(config_path=self.yaml_path)
        if not mc.start(timeout=30):
            node.status = "error"
            node.consecutive_failures += 1
            return False
        # 切换到这个节点 (GLOBAL 组有全部节点可选)
        if not mc.switch_node(node.name):
            mc.stop()
            node.status = "error"
            node.consecutive_failures += 1
            return False
        node.mc = mc
        # 用 HTTP 代理格式 (curl_cffi 的 socks5 有 TLS 兼容问题, HTTP CONNECT 更稳)
        # mihomo mixed_port 同时支持 SOCKS5 和 HTTP CONNECT
        node.proxy_url = f"http://127.0.0.1:{mc.mixed_port}"
        node.status = "idle"
        return True

    def acquire(self) -> Optional[NodeState]:
        """
        租一个可用节点 (线程安全)
        ★ 提交时预扣积分 (2026-06-22 风控实测)
        DOLA 超过 6 次/天/IP 后, conv_id 仍成功但视频永不生成
        所以积分必须在提交前扣除, 不能等视频成功才扣
        """
        with self._lock:
            now = time.time()
            candidates = [n for n in self.nodes if n.available()]
            if not candidates:
                return None
            # 按积分降序 + last_used 升序 排序 (优先用积分多的节点)
            candidates.sort(key=lambda n: (-n.credits_remaining, n.last_used))
            node = candidates[0]
            node.inflight += 1
            node.credits_remaining -= 1  # ★ 预扣积分
            node.total_submitted += 1
            node.last_used = now
            node.status = "in_use"
            return node

    def release(self, node: NodeState, success: bool, timeout: bool = False):
        """
        归还节点 (线程安全)

        积分已在 acquire 时预扣, release 不再扣。
        release 负责:
          - success: 重置 failure, 计 total_generated
          - 失败: 增加 failure (但积分不退, 因为提交已经消耗了风控配额)
          - timeout: 连续超时 2 次 → 标记冷却 (该 IP 可能被风控)
        """
        with self._lock:
            node.inflight = max(0, node.inflight - 1)
            if success:
                node.consecutive_failures = 0
                node.total_generated += 1
                node.status = "idle"
            elif timeout:
                # 视频超时不生成 = 可能被频率风控
                node.consecutive_failures += 1
                if node.consecutive_failures >= 2:
                    # 连续 2 次超时 → 该 IP 可能被风控, 冷却到明天
                    node.rate_limited_until = node.credits_reset_at
                    node.status = "cooldown"
                    node.credits_remaining = 0  # 积分清零 (已被风控)
                else:
                    node.status = "idle"
            else:
                # 提交级失败 (网络/SSL 等), 不是风控
                node.consecutive_failures += 1
                if node.consecutive_failures >= 3:
                    node.rate_limited_until = time.time() + 3600
                    node.status = "cooldown"
                else:
                    node.status = "idle"

    def ensure_started(self, node: NodeState) -> bool:
        """确保节点的 MiniClash 已启动 (线程安全包装)"""
        with self._lock:
            return self._ensure_mini_clash(node)

    def snapshot(self) -> List[dict]:
        """获取所有节点状态快照 (线程安全)"""
        with self._lock:
            return [n.to_dict() for n in self.nodes]

    def stats(self) -> dict:
        """汇总统计"""
        with self._lock:
            total = len(self.nodes)
            available = sum(1 for n in self.nodes if n.available())
            total_credits = sum(n.credits_remaining for n in self.nodes)
            inflight = sum(n.inflight for n in self.nodes)
            cooldown = sum(1 for n in self.nodes if n.status == "cooldown")
            error = sum(1 for n in self.nodes if n.status == "error")
            total_generated = sum(n.total_generated for n in self.nodes)
            return {
                "total_nodes": total,
                "available_nodes": available,
                "total_credits_remaining": total_credits,
                "active_tasks": inflight,
                "cooldown_nodes": cooldown,
                "error_nodes": error,
                "total_videos_generated": total_generated,
            }

    def stop(self):
        """关闭所有 MiniClash 实例"""
        with self._lock:
            for node in self.nodes:
                if node.mc:
                    try:
                        node.mc.stop()
                    except Exception:
                        pass
                    node.mc = None
                    node.proxy_url = ""
                    node.status = "idle"

    def prewarm(self, count: int = None):
        """
        并发预热前 N 个节点 (启动 mihomo 进程, 避免首次任务等 30s)
        在服务启动时调用, 非阻塞 (用线程池并发预热)
        """
        count = count or config.PREWARM_NODES
        if count <= 0:
            return 0
        # 选前 count 个可用节点 (积分最多的)
        with self._lock:
            candidates = [n for n in self.nodes if n.available() and not n.mc]
            candidates.sort(key=lambda n: -n.credits_remaining)
            candidates = candidates[:count]
        if not candidates:
            return 0
        print(f"[*] NodePool prewarming {len(candidates)} nodes (concurrent)...")

        # 并发预热 (每个节点启动 mihomo 要 ~5s, 串行太慢)
        from concurrent.futures import ThreadPoolExecutor, as_completed
        started = [0]  # 用 list 包装以便闭包修改

        def _prewarm_one(node):
            try:
                with self._lock:
                    if node.mc:  # 已被其他线程启动
                        return
                if self._ensure_mini_clash(node):
                    started[0] += 1
                    print(f"    ✓ prewarmed: {node.name} ({node.proxy_url})")
                else:
                    print(f"    ✗ prewarm failed: {node.name}")
            except Exception as e:
                print(f"    ✗ prewarm error: {node.name}: {e}")

        with ThreadPoolExecutor(max_workers=min(count, 4)) as pool:
            list(pool.map(_prewarm_one, candidates))
        print(f"[*] NodePool prewarm done: {started[0]}/{len(candidates)} nodes ready")
        return started[0]

    def active_worker_count(self) -> int:
        """当前正在执行任务的节点数 (用于队列位置计算)"""
        with self._lock:
            return sum(1 for n in self.nodes if n.inflight > 0)

    def estimate_wait_time(self) -> dict:
        """估算等待时间 (供前端展示, 含 DOLA 时段规律)"""
        with self._lock:
            available = sum(1 for n in self.nodes if n.available())
            inflight = sum(n.inflight for n in self.nodes)
            total_credits = sum(n.credits_remaining for n in self.nodes)
        # DOLA 排队时间 (按时段)
        slot = config.get_time_slot()
        dola_eta = slot["estimated_seconds"]
        if available > 0:
            return {"queued": False,
                    "estimated_wait": dola_eta,
                    "estimated_wait_label": f"~{slot['estimated_minutes']} 分钟 ({slot['label']})",
                    "available_workers": available,
                    "time_slot": slot}
        else:
            return {"queued": True,
                    "estimated_wait": dola_eta,
                    "estimated_wait_label": f"~{slot['estimated_minutes']} 分钟 ({slot['label']})",
                    "available_workers": 0,
                    "queue_position": inflight,
                    "time_slot": slot}


# 全局单例 (整个服务共享一个池)
_pool: Optional[NodePool] = None


def get_pool() -> NodePool:
    """获取全局节点池单例 (首次调用会加载节点 + 预热)"""
    global _pool
    if _pool is None:
        _pool = NodePool()
        count = _pool.load_nodes()
        print(f"[*] NodePool loaded {count} nodes from {_pool.yaml_path}")
        # 预热前 N 个节点 (并发启动 mihomo, 避免首次任务等 30s)
        if config.PREWARM_NODES > 0:
            _pool.prewarm(config.PREWARM_NODES)
    return _pool
