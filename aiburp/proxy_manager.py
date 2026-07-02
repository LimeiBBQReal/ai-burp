"""
V4 代理管理器 - 包装 MiniClash/NodePool, 为 TrafficEngine 提供代理能力.

融合自 qwen2API/proxy 模块. 红队场景:
    - 匿名化: 所有扫描通过代理节点发出, 隐藏真实 IP
    - IP 轮换: 不同请求走不同出口 IP, 避免封禁
    - 地理伪装: 从不同国家扫描, 测试地域限制
    - 代理池管理: 自动测活/切换/积分跟踪

两种代理模式:
    1. MiniClash (mihomo): 启动本地 mihomo 进程, 所有流量走 V2Ray/Trojan 节点
       - 适合: 需要 V2Ray/Trojan/Hysteria2 等协议
       - 用法: ProxyManager.start_clash() → 拿 socks5://127.0.0.1:port
    2. HTTP/SOCKS5 代理池: 直接用代理列表 (不需要 mihomo)
       - 适合: 已有 HTTP/SOCKS5 代理列表
       - 用法: ProxyManager.add_proxies(["1.2.3.4:8080", ...])

与 TrafficEngine 集成:
    engine = TrafficEngine(proxy_manager=pm)
    # 所有 adapter 的请求都会通过代理
"""

import os
import time
import random
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field


@dataclass
class ProxyNode:
    """代理节点"""
    url: str               # http://1.2.3.4:8080 或 socks5://1.2.3.4:1080
    country: str = ""      # 国家 (US/JP/SG/...)
    alive: bool = True     # 是否存活
    last_check: float = 0  # 最后检测时间
    latency_ms: float = 0  # 延迟
    fail_count: int = 0    # 连续失败次数
    success_count: int = 0 # 成功次数


class ProxyManager:
    """
    V4 代理管理器.

    用法 1 (MiniClash/mihomo):
        pm = ProxyManager()
        pm.start_clash(config_path="aiburp/proxy/yaml/dola_capable.yaml")
        proxy_url = pm.get_proxy()  # socks5://127.0.0.1:7890

    用法 2 (直连 HTTP/SOCKS5 代理):
        pm = ProxyManager()
        pm.add_proxies(["http://1.2.3.4:8080", "socks5://5.6.7.8:1080"])
        proxy_url = pm.get_proxy()  # 随机返回一个

    与 TrafficEngine:
        engine = TrafficEngine(proxy_manager=pm)
    """

    def __init__(self, auto_harvest: bool = True):
        """
        Args:
            auto_harvest: 当节点全死时是否自动从 proxyscrape 拉取新节点
        """
        self._nodes: List[ProxyNode] = []
        self._clash = None  # MiniClash 实例
        self._clash_url: str = ""  # MiniClash 的代理 URL
        self._mode: str = "none"  # "clash" / "pool" / "none"
        self._auto_harvest = auto_harvest
        self._fallback_urls: List[str] = []  # 直连 HTTP 代理 (mihomo 失败时 fallback)

    # ============================================================
    # MiniClash 模式
    # ============================================================

    def start_clash(self, config_path: str = None,
                    mixed_port: int = 7890) -> str:
        """
        启动 MiniClash (mihomo), 返回代理 URL.

        Args:
            config_path: Clash YAML 配置路径 (默认 -> proxy/yaml/proxy_alive.yaml)
            mixed_port: 混合端口 (SOCKS5+HTTP)

        Returns:
            代理 URL, 如 "socks5h://127.0.0.1:7890"
        """
        from .proxy.mini_clash import MiniClash

        if config_path is None:
            # 默认配置: proxy_alive.yaml (由 harvester 维护)
            default = os.path.join(os.path.dirname(__file__),
                                   "proxy", "yaml", "proxy_alive.yaml")
            config_path = default if os.path.exists(default) else None

        self._clash = MiniClash(
            config_path=config_path,
            mixed_port=mixed_port,
        )
        self._clash.start()
        self._clash_url = f"socks5h://127.0.0.1:{self._clash.mixed_port}"
        self._mode = "clash"
        return self._clash_url

    def clash_switch_node(self, node_name: str):
        """切换 Clash 节点"""
        if self._clash:
            self._clash.switch_node(node_name)

    def clash_list_nodes(self) -> List[str]:
        """列出可用节点"""
        if self._clash:
            return self._clash.list_nodes()
        return []

    def clash_get_exit_ip(self) -> str:
        """获取当前出口 IP"""
        if self._clash:
            return self._clash.get_exit_ip()
        return ""

    def stop_clash(self):
        """停止 Clash"""
        if self._clash:
            self._clash.stop()
            self._clash = None
        self._clash_url = ""
        if self._mode == "clash":
            self._mode = "none"

    def start_with_harvest_fallback(self) -> str:
        """
        启动代理, 带自动 harvest fallback.

        策略:
            1. 尝试 mihomo (proxy_alive.yaml)
            2. 如果 mihomo 失败 → 运行 harvester 拉取新节点
            3. 如果 harvester 也失败 → 直接 HTTP 代理模式 (无需 mihomo)

        Returns:
            代理 URL
        """
        # Phase 1: mihomo
        try:
            url = self.start_clash()
            if url:
                # 快速验证出口
                import requests as _req
                try:
                    r = _req.get("http://httpbin.org/ip",
                                proxies={"http": url, "https": url}, timeout=8)
                    if r.status_code == 200:
                        return url
                except Exception:
                    self.stop_clash()
        except Exception:
            pass

        # Phase 2: auto-harvest
        if not self._auto_harvest:
            raise RuntimeError("代理不可用, auto_harvest=False 不自动拉取")

        print("[ProxyManager] mihomo 失败, 启动 auto-harvest...")
        try:
            from .proxy.proxy_harvester import collect, write_config
            alive = collect(require_ssl=False, min_alive=3, timeout=4.0)
            if alive and len(alive) >= 3:
                write_config(alive)
                # 重新启动 mihomo
                url = self.start_clash()
                if url:
                    return url
        except Exception as e:
            print(f"[ProxyManager] harvest 失败: {e}")

        # Phase 3: 直连 HTTP 代理 (无需 mihomo)
        print("[ProxyManager] 切换直连 HTTP 代理模式...")
        self._mode = "pool"
        self._fallback_urls = self._fetch_direct_fallback()
        if self._fallback_urls:
            return self._fallback_urls[0]
        raise RuntimeError("所有代理模式均不可用")

    def _fetch_direct_fallback(self) -> List[str]:
        """从 proxyscrape 快速获取直连 HTTP 代理."""
        import requests as _req
        try:
            r = _req.get(
                "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all",
                timeout=8,
            )
            candidates = [l.strip() for l in r.text.split("\n") if ":" in l.strip()]
            # 快速测活
            alive = []
            from concurrent.futures import ThreadPoolExecutor, as_completed

            def test(proxy):
                url = f"http://{proxy}"
                try:
                    r2 = _req.get("http://httpbin.org/ip",
                                 proxies={"http": url, "https": url}, timeout=3)
                    if r2.status_code == 200:
                        return url
                except:
                    pass
                return None

            with ThreadPoolExecutor(max_workers=20) as pool:
                futs = {pool.submit(test, p): p for p in candidates[:40]}
                for f in as_completed(futs, timeout=20):
                    r = f.result()
                    if r:
                        alive.append(r)
                        if len(alive) >= 3:
                            break
            return alive
        except Exception:
            return []

    def is_active(self) -> bool:
        """代理是否可用."""
        return self.get_proxy() is not None

    # ============================================================
    # 代理池模式 (直连 HTTP/SOCKS5)
    # ============================================================

    def add_proxies(self, proxies: List[str], country: str = ""):
        """
        添加代理列表.

        Args:
            proxies: ["http://1.2.3.4:8080", "socks5://5.6.7.8:1080"]
            country: 国家标识
        """
        for url in proxies:
            # 标准化 URL (补协议)
            if not url.startswith(("http://", "https://", "socks5://", "socks5h://")):
                url = f"http://{url}"
            self._nodes.append(ProxyNode(url=url, country=country))
        if self._nodes and self._mode == "none":
            self._mode = "pool"

    def load_from_file(self, filepath: str):
        """从文件加载代理列表 (每行一个代理)"""
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.add_proxies([line])

    def load_from_yaml(self, yaml_path: str):
        """从 Clash YAML 加载代理 (提取 server:port 构造 HTTP 代理)"""
        import yaml
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        for proxy in data.get("proxies", []):
            server = proxy.get("server", "")
            port = proxy.get("port", 0)
            ptype = proxy.get("type", "http")
            if server and port:
                # 仅对 http/socks5 类型直接构造 URL, 其他类型需走 clash
                if ptype == "http":
                    url = f"http://{server}:{port}"
                elif ptype in ("socks5", "socks5-h"):
                    url = f"socks5h://{server}:{port}"
                else:
                    # vmess/trojan/ss 等非直连协议, 跳过 (需走 clash 本地混合端口)
                    continue
                self._nodes.append(ProxyNode(
                    url=url,
                    country=proxy.get("name", "")[:2].upper(),
                ))
        if self._nodes and self._mode == "none":
            self._mode = "pool"

    # ============================================================
    # 获取代理 (统一入口, 不再有双定义)
    # ============================================================

    def get_proxy(self, exclude: Optional[List[str]] = None) -> Optional[str]:
        """
        获取一个代理 URL.

        Args:
            exclude: 要排除的代理 URL 列表 (避免连续用同一个)

        Returns:
            代理 URL, 或 None (无可用代理)
        """
        if self._mode == "clash":
            return self._clash_url

        if self._mode == "pool":
            # 优先从 _nodes 池中选 (带健康状态)
            available = [n for n in self._nodes
                         if n.alive and n.url not in (exclude or [])]
            if available:
                # 优先选延迟低/成功率高的
                available.sort(key=lambda n: (n.fail_count, n.latency_ms))
                return available[0].url
            # 兜底: 从 _fallback_urls 随机选 (直连模式采集的)
            if self._fallback_urls:
                candidates = [u for u in self._fallback_urls
                              if u not in (exclude or [])]
                if candidates:
                    return random.choice(candidates)

        return None  # 无代理模式

    def get_proxies(self, count: int = 10) -> List[str]:
        """获取多个代理 URL"""
        if self._mode == "clash":
            return [self._clash_url] * count
        available = [n.url for n in self._nodes if n.alive]
        return available[:count]

    # ============================================================
    # 健康检查
    # ============================================================

    def mark_result(self, proxy_url: str, success: bool, latency_ms: float = 0):
        """标记代理的使用结果"""
        for n in self._nodes:
            if n.url == proxy_url:
                if success:
                    n.success_count += 1
                    n.fail_count = 0
                else:
                    n.fail_count += 1
                    if n.fail_count >= 3:
                        n.alive = False
                n.latency_ms = latency_ms or n.latency_ms
                n.last_check = time.time()
                break

    def health_check(self, test_url: str = "https://httpbin.org/ip",
                     timeout: float = 5.0) -> Dict[str, Any]:
        """
        批量健康检查.

        Returns:
            {"alive": N, "dead": M, "total": T}
        """
        import requests as _requests

        alive = 0
        dead = 0
        for n in self._nodes:
            try:
                proxies = {"http": n.url, "https": n.url}
                r = _requests.get(test_url, proxies=proxies, timeout=timeout,
                                  verify=False)
                if r.status_code == 200:
                    n.alive = True
                    n.fail_count = 0
                    alive += 1
                else:
                    n.alive = False
                    dead += 1
            except Exception:
                n.alive = False
                dead += 1

        return {"alive": alive, "dead": dead, "total": len(self._nodes)}

    # ============================================================
    # 状态
    # ============================================================

    def stats(self) -> Dict[str, Any]:
        """统计信息"""
        if self._mode == "clash":
            return {
                "mode": "clash",
                "proxy_url": self._clash_url,
                "exit_ip": self.clash_get_exit_ip(),
            }
        return {
            "mode": self._mode,
            "total": len(self._nodes),
            "alive": sum(1 for n in self._nodes if n.alive),
            "dead": sum(1 for n in self._nodes if not n.alive),
        }

    @property
    def enabled(self) -> bool:
        """是否启用了代理"""
        return self._mode != "none"

    def close(self):
        """清理"""
        self.stop_clash()
        self._nodes.clear()
        self._mode = "none"
