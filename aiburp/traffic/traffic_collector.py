"""
流量采集器 — 把 MITM 代理 + TrafficJournal + TrafficAnalyzer 打包成一个组件.

"所有流量走 Burp 式采集让 LLM 决策" 的核心实现.

用法:
    from aiburp.traffic.traffic_collector import TrafficCollector
    from aiburp.traffic.traffic_journal import TrafficJournal

    collector = TrafficCollector(port=8080, journal=TrafficJournal())
    collector.start()
    # ... 让浏览器/工具配置代理到 localhost:8080 ...
    # 所有流量自动进入 journal
    summary = collector.get_summary()
    patterns = collector.detect_patterns()
    collector.stop()
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CollectorStats:
    """采集器统计."""
    total_captured: int = 0
    findings_detected: int = 0
    start_time: float = 0.0
    running_seconds: float = 0.0
    patterns_found: int = 0


class TrafficCollector:
    """
    流量采集器 — Burp 式持续流量监听.

    包装:
        - Proxy (MITM 代理)
        - TrafficJournal (语义流量日志)
        - TrafficAnalyzer (被动分析, 可选)

    提供统一的 start/stop/get_summary 接口供 Agent 使用.
    """

    def __init__(self, port: int = 8080, journal=None,
                 host: str = "127.0.0.1", history=None):
        """
        Args:
            port: 代理监听端口
            journal: TrafficJournal 实例 (如 None 自动创建)
            host: 代理监听地址
            history: 可选的 History 实例 (如 None, 自动创建内存版)
        """
        self.port = port
        self.host = host
        self._proxy = None
        self._running = False

        # Journal
        if journal is not None:
            self.journal = journal
        else:
            from .traffic_journal import TrafficJournal
            self.journal = TrafficJournal(max_entries=500)

        # History
        if history is not None:
            self.history = history
        else:
            from ..core.history import History
            self.history = History(project="_traffic_collector")

        self.stats = CollectorStats()

    def start(self, blocking: bool = False) -> Dict:
        """
        启动流量采集器.

        Args:
            blocking: 是否阻塞当前线程

        Returns:
            {"success": bool, "message": str, "port": int}
        """
        if self._running:
            return {"success": False, "message": "采集器已在运行", "port": self.port}

        try:
            from ..core.proxy import Proxy, ProxyConfig

            config = ProxyConfig(host=self.host, port=self.port)
            config.exclude_extensions = [
                ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico",
                ".woff", ".woff2", ".ttf", ".eot", ".svg", ".mp4", ".webp",
            ]

            self._proxy = Proxy(
                history=self.history,
                config=config,
                journal=self.journal,
            )

            result = self._proxy.start(blocking=blocking)
            self._running = result.get("success", False)
            self.stats.start_time = time.time()

            if self._running:
                logger.info(f"TrafficCollector started on {self.host}:{self.port}")
                return {"success": True, "message": f"采集器已启动于 {self.host}:{self.port}",
                        "port": self.port}
            else:
                return {"success": False, "message": result.get("error", "启动失败"),
                        "port": self.port}

        except ImportError as e:
            return {"success": False, "message": f"启动失败 (缺少依赖): {e}", "port": self.port}
        except Exception as e:
            return {"success": False, "message": f"启动异常: {e}", "port": self.port}

    def stop(self) -> Dict:
        """
        停止流量采集器.

        Returns:
            {"success": bool, "message": str, "stats": CollectorStats}
        """
        if not self._running or not self._proxy:
            return {"success": False, "message": "采集器未在运行", "stats": self.stats}

        try:
            self._proxy.stop()
        except Exception as e:
            logger.warning(f"停止代理时异常: {e}")

        self._running = False
        self.stats.running_seconds = round(time.time() - self.stats.start_time, 1)
        self.stats.total_captured = len(self.journal)

        return {
            "success": True,
            "message": f"采集器已停止 (运行 {self.stats.running_seconds}s, "
                      f"捕获 {self.stats.total_captured} 条)",
            "stats": {
                "total_captured": self.stats.total_captured,
                "findings_detected": self.stats.findings_detected,
                "running_seconds": self.stats.running_seconds,
                "patterns_found": self.stats.patterns_found,
            },
        }

    # ============================================================
    # 状态查询
    # ============================================================

    @property
    def is_running(self) -> bool:
        return self._running

    def get_summary(self, last_n: int = 30) -> str:
        """
        获取当前流量摘要 (供 LLM 消费).

        Args:
            last_n: 取最近 N 条

        Returns:
            格式化的流量摘要字符串
        """
        if not self.journal or len(self.journal) == 0:
            return "暂无流量数据"

        summary = self.journal.llm_summary(last_n=last_n)
        self.stats.total_captured = len(self.journal)
        return summary

    def detect_patterns(self, window: int = 30) -> List[Dict]:
        """
        从当前流量中检测模式 (供 LLM 决策).

        Args:
            window: 分析窗口

        Returns:
            模式发现列表
        """
        if not self.journal:
            return []
        patterns = self.journal.detect_patterns(window=window)
        self.stats.patterns_found = len(patterns)
        return patterns

    def analyze_traffic(self) -> Dict:
        """
        对当前流量执行被动分析.

        Returns:
            AnalysisReport dict
        """
        try:
            from .traffic_analyzer import TrafficAnalyzer
            analyzer = TrafficAnalyzer()
            # 从 journal 提取最近流量
            entries = list(self.journal._entries)[-50:] if hasattr(self.journal, '_entries') else []
            traffic_list = []
            for e in entries:
                traffic_list.append({
                    "url": getattr(e, 'url', ''),
                    "method": getattr(e, 'method', 'GET'),
                    "resp_status": getattr(e, 'resp_status', 0),
                    "resp_body": getattr(e, 'body', ''),
                })
            if not traffic_list:
                return {"ok": False, "message": "暂无流量数据"}

            report = analyzer.analyze_batch(traffic_list)
            self.stats.findings_detected = len(report.findings) if report else 0
            return {
                "ok": True,
                "total_analyzed": len(traffic_list),
                "findings": [str(f) for f in (report.findings if report else [])],
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_status(self) -> Dict:
        """获取采集器完整状态."""
        self.stats.total_captured = len(self.journal) if self.journal else 0
        self.stats.running_seconds = round(
            time.time() - self.stats.start_time, 1
        ) if self.stats.start_time else 0

        return {
            "running": self._running,
            "port": self.port,
            "host": self.host,
            "captured": self.stats.total_captured,
            "running_seconds": self.stats.running_seconds,
            "patterns_found": self.stats.patterns_found,
            "findings_detected": self.stats.findings_detected,
        }

    def get_recent_urls(self, n: int = 20) -> List[str]:
        """获取最近 N 个 URL."""
        urls = []
        if self.journal:
            for entry in list(self.journal._entries)[-n:]:
                u = getattr(entry, 'url', '') or getattr(entry, 'target', '')
                if u:
                    urls.append(u)
        return urls


# ============================================================
# 快捷函数
# ============================================================

def create_collector(port: int = 8080, journal=None) -> TrafficCollector:
    """创建流量采集器的快捷函数."""
    return TrafficCollector(port=port, journal=journal)