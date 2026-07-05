"""
Recon Pipeline V2 - 协议探测引擎

统一调度协议探测，对资产池进行协议识别。
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

from .base import BaseProtocolProbe, ProbeResult
from .registry import ProtocolRegistry, auto_register_builtin


class ProtocolProbeEngine:
    """
    协议探测引擎

    职责:
    1. 加载所有已注册的协议模块
    2. 根据端口匹配可能的协议
    3. 并发执行探测
    4. 汇总结果
    """

    def __init__(self, max_workers: int = 50):
        self.registry = ProtocolRegistry()
        self.max_workers = max_workers

        # 自动注册内置协议
        auto_register_builtin()

        # 构建端口索引
        self._port_index = self.registry.build_port_index()

    def probe_assets(self, assets: List[dict]) -> Dict[str, List[dict]]:
        """
        对资产池执行协议探测

        Args:
            assets: 资产列表，每个资产包含 ip 和 port
                   例如: [{"ip": "1.2.3.4", "port": 80}, ...]

        Returns:
            按协议分组的资产: {"http": [...], "ssh": [...], ...}
        """
        # 按端口分组资产
        port_groups = defaultdict(list)
        for asset in assets:
            port = asset.get("port")
            if port:
                port_groups[port].append(asset)

        # 结果收集
        results = defaultdict(list)

        # 对每个端口执行探测
        for port, group in port_groups.items():
            # 获取该端口可能的协议
            protocol_names = self.registry.get_by_port(port)

            if not protocol_names:
                # 未知端口，尝试 HTTP 探测
                protocol_names = ["http"]

            for proto_name in protocol_names:
                probe_cls = self.registry.get(proto_name)
                if not probe_cls:
                    continue

                probe = probe_cls()
                matched = self._probe_group(probe, group)

                if matched:
                    results[proto_name].extend(matched)

        return dict(results)

    def probe_single(self, ip: str, port: int) -> Optional[ProbeResult]:
        """
        对单个 IP:Port 执行协议探测

        尝试所有可能匹配该端口的协议。
        """
        protocol_names = self.registry.get_by_port(port)

        if not protocol_names:
            # 尝试常见协议
            protocol_names = ["http", "https"]

        for proto_name in protocol_names:
            probe_cls = self.registry.get(proto_name)
            if not probe_cls:
                continue

            probe = probe_cls()
            result = probe.probe(ip, port)

            if result.is_match:
                return result

        return None

    def _probe_group(self, probe: BaseProtocolProbe, assets: List[dict]) -> List[dict]:
        """
        对一组资产执行同一种协议探测

        使用线程池并发执行，但受协议模块的 max_concurrency 限制。
        """
        results = []
        concurrency = min(probe.max_concurrency, self.max_workers)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {}
            for asset in assets:
                ip = asset.get("ip", "")
                port = asset.get("port", 0)
                if ip and port:
                    future = executor.submit(probe.probe, ip, port)
                    futures[future] = asset

            for future in as_completed(futures):
                try:
                    result = future.result(timeout=probe.timeout + 2)
                    if result.is_match:
                        asset = futures[future]
                        asset["protocol"] = result.protocol
                        asset["banner"] = result.banner
                        asset["version"] = result.version
                        asset["protocol_config"] = result.config
                        results.append(asset)
                except Exception:
                    pass

        return results

    def probe_with_fallback(self, ip: str, port: int) -> Optional[ProbeResult]:
        """
        带降级的探测

        先尝试精确匹配的协议，
    如果不匹配则尝试常见协议。
        """
        # 第一轮: 精确匹配
        result = self.probe_single(ip, port)
        if result and result.is_match:
            return result

        # 第二轮: 尝试常见协议
        common_protocols = ["http", "https", "ssh"]
        for proto_name in common_protocols:
            probe_cls = self.registry.get(proto_name)
            if not probe_cls:
                continue

            # 跳过已经尝试过的
            if proto_name in self.registry.get_by_port(port):
                continue

            probe = probe_cls()
            result = probe.probe(ip, port)
            if result.is_match:
                return result

        return None

    def list_protocols(self) -> List[str]:
        """列出所有已注册的协议"""
        return self.registry.list_protocols()

    def get_protocol_for_port(self, port: int) -> Optional[str]:
        """获取端口对应的协议"""
        names = self.registry.get_by_port(port)
        return names[0] if names else None


# 便捷函数
def probe_assets(assets: List[dict], max_workers: int = 50) -> Dict[str, List[dict]]:
    """便捷探测函数"""
    engine = ProtocolProbeEngine(max_workers=max_workers)
    return engine.probe_assets(assets)
