"""
反溯源模块 (AntiTrace) - 红队对抗防护.

蓝队溯源的 5 条路径:
    1. 网络: 源 IP → 注册信息 → 定位
    2. 指纹: TLS JA3 / User-Agent → 工具识别
    3. 行为: 扫描节奏 / payload 模式 → 自动化告警
    4. 基础设施: OOB 域名 / C2 → 反查
    5. 残留: 日志中的特征字符串

本模块提供的防护:
    - IP 自动轮换 (配合 ProxyManager)
    - User-Agent 轮换池
    - 请求间隔随机化 (避免固定节奏)
    - TLS 指纹随机化 (JA3 多态)
    - 请求头去标识 (清除指纹头)
    - OOB 域名建议 (自建 vs 公共)
    - 流量整形 (模拟正常浏览器行为)
"""

import random
import time
import asyncio
from typing import Optional, Dict, List, Callable
from dataclasses import dataclass, field


# ============================================================
#                   User-Agent 轮换池
# ============================================================

# 真实浏览器 UA (最新版, 按使用频率排序)
USER_AGENTS = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    # Chrome (Mac)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    # Safari (Mac)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    # Mobile Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
]


# 需要清除的指纹头 (防止暴露扫描器身份)
FINGERPRINT_HEADERS_TO_REMOVE = [
    "X-Scanner",          # 扫描器特征
    "X-Requested-With",   # AJAX 特征 (某些扫描器会留)
    "X-Scan-Memo",        # Acunetix
    "Origin",             # CORS 扫描特征 (非必要时清除)
]

# 需要替换的安全相关头
SAFE_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}


@dataclass
class TraceRiskReport:
    """溯源风险评估"""
    risk_level: str = "low"     # low / medium / high / critical
    risks: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "risk_level": self.risk_level,
            "risks": self.risks,
            "recommendations": self.recommendations,
        }


class AntiTrace:
    """
    反溯源引擎.

    用法:
        # 基础用法: 给请求加防护头
        anti = AntiTrace()
        headers = anti.sanitize_headers({"User-Agent": "python-requests/2.28"})

        # 进阶: 配合 ProxyManager 做 IP 轮换
        anti = AntiTrace(proxy_manager=pm, auto_rotate_ip=True, rotate_interval=30)
        await anti.start()  # 启动后台 IP 轮换

        # 获取安全请求头
        headers = anti.get_safe_headers()

        # 随机延迟
        await anti.random_delay()  # 0.5-3s 随机延迟
    """

    def __init__(
        self,
        proxy_manager=None,
        auto_rotate_ip: bool = False,
        rotate_interval: float = 30.0,
        random_ua: bool = True,
        random_delay_range: tuple = (0.5, 3.0),
    ):
        """
        Args:
            proxy_manager:     ProxyManager 实例 (IP 轮换用)
            auto_rotate_ip:    是否自动定时轮换 IP
            rotate_interval:   IP 轮换间隔 (秒)
            random_ua:         是否随机 User-Agent
            random_delay_range: 随机延迟范围 (min, max) 秒
        """
        self.pm = proxy_manager
        self.auto_rotate_ip = auto_rotate_ip
        self.rotate_interval = rotate_interval
        self.random_ua = random_ua
        self.delay_min, self.delay_max = random_delay_range

        self._current_ua: str = random.choice(USER_AGENTS)
        self._last_rotate: float = 0
        self._rotate_task: Optional[asyncio.Task] = None
        self._request_count: int = 0

    # ============================================================
    #                  请求头安全化
    # ============================================================

    def get_safe_headers(self, extra: Optional[Dict] = None) -> Dict[str, str]:
        """
        获取安全的请求头组合.

        - 随机 User-Agent
        - 清除指纹头
        - 添加正常浏览器头
        """
        headers = dict(SAFE_HEADERS)

        # 随机 UA
        if self.random_ua:
            headers["User-Agent"] = self._rotate_ua()
        else:
            headers["User-Agent"] = self._current_ua

        # 合并用户自定义头
        if extra:
            headers.update(extra)

        return headers

    def sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        清洗请求头 (移除指纹头, 替换 UA).

        适用于已有请求头需要净化的场景.
        """
        cleaned = {}
        for k, v in headers.items():
            # 跳过指纹头
            if k in FINGERPRINT_HEADERS_TO_REMOVE:
                continue
            # 替换 UA
            if k.lower() == "user-agent" and self.random_ua:
                cleaned[k] = self._rotate_ua()
                continue
            # 替换 python-requests UA
            if k.lower() == "user-agent" and ("python" in v.lower() or "httpx" in v.lower()):
                cleaned[k] = self._rotate_ua()
                continue
            cleaned[k] = v

        # 补充安全头
        for k, v in SAFE_HEADERS.items():
            if k not in cleaned:
                cleaned[k] = v

        return cleaned

    # ============================================================
    #                  随机延迟 (流量整形)
    # ============================================================

    async def random_delay(self):
        """
        随机延迟 — 避免固定扫描节奏.

        模拟人类浏览行为:
        - 基础延迟 (delay_min ~ delay_max)
        - 偶尔长停顿 (模拟阅读页面)
        - 偶尔快速连续 (模拟翻页)
        """
        self._request_count += 1

        # 90% 正常延迟
        if random.random() < 0.9:
            delay = random.uniform(self.delay_min, self.delay_max)
        # 7% 长停顿 (模拟阅读 3-8 秒)
        elif random.random() < 0.77:
            delay = random.uniform(3.0, 8.0)
        # 3% 快速连续 (模拟翻页 0.1-0.3 秒)
        else:
            delay = random.uniform(0.1, 0.3)

        await asyncio.sleep(delay)

    # ============================================================
    #                  IP 自动轮换
    # ============================================================

    async def start(self):
        """启动后台 IP 自动轮换"""
        if self.auto_rotate_ip and self.pm and self.pm.enabled:
            self._rotate_task = asyncio.create_task(self._rotate_loop())

    async def stop(self):
        """停止 IP 轮换"""
        if self._rotate_task:
            self._rotate_task.cancel()
            try:
                await self._rotate_task
            except asyncio.CancelledError:
                pass
            self._rotate_task = None

    async def _rotate_loop(self):
        """后台 IP 轮换循环"""
        while True:
            await asyncio.sleep(self.rotate_interval)
            try:
                self.rotate_ip()
            except Exception:
                pass

    def rotate_ip(self):
        """
        手动轮换 IP.

        MiniClash 模式: 切换到下一个节点.
        代理池模式: 标记当前代理, 切换到下一个.
        """
        if not self.pm or not self.pm.enabled:
            return

        if self.pm._mode == "clash":
            nodes = self.pm.clash_list_nodes()
            if nodes:
                # 随机选一个不同的节点
                current = self.pm.clash_get_exit_ip()
                candidates = [n for n in nodes if n != current]
                if candidates:
                    new_node = random.choice(candidates)
                    self.pm.clash_switch_node(new_node)
                    self._last_rotate = time.time()

        self._last_rotate = time.time()

    def should_rotate(self) -> bool:
        """是否该轮换了 (超过间隔 或 请求量过大)"""
        if time.time() - self._last_rotate > self.rotate_interval:
            return True
        if self._request_count > 50:  # 每 50 请求轮换一次
            return True
        return False

    # ============================================================
    #                  溯源风险评估
    # ============================================================

    def assess_risk(self) -> TraceRiskReport:
        """
        评估当前配置的溯源风险.

        检查:
        - 是否用了代理
        - 是否有指纹泄露
        - 是否有固定节奏
        - OOB 是否安全
        """
        report = TraceRiskReport()
        risks = []
        recommendations = []

        # 1. 代理检查
        if not self.pm or not self.pm.enabled:
            risks.append("直连模式 - 真实 IP 暴露 (最高风险)")
            recommendations.append("启用 ProxyManager 或设置 HTTP_PROXY/SOCKS5_PROXY")
            report.risk_level = "critical"
        else:
            stats = self.pm.stats()
            if stats.get("mode") == "clash":
                recommendations.append("MiniClash 模式: 定期 clash_switch_node 轮换出口 IP")
            elif stats.get("alive", 0) < 2:
                risks.append(f"代理池只有 {stats.get('alive', 0)} 个存活代理")
                recommendations.append("增加代理数量 (至少 5 个)")
                if report.risk_level == "low":
                    report.risk_level = "medium"

        # 2. UA 检查
        if not self.random_ua:
            risks.append("固定 User-Agent - 可被追踪")
            recommendations.append("启用 random_ua=True")
            if report.risk_level == "low":
                report.risk_level = "medium"

        # 3. 速率检查
        if self.delay_max < 1.0:
            risks.append("请求间隔过短 (<1s) - 易触发速率告警")
            recommendations.append("增大 random_delay_range 到 (1.0, 5.0)")
            if report.risk_level == "low":
                report.risk_level = "medium"

        # 4. IP 轮换检查
        if self.pm and self.pm.enabled and not self.auto_rotate_ip:
            risks.append("未启用自动 IP 轮换 - 长时间用同一 IP")
            recommendations.append("启用 auto_rotate_ip=True, rotate_interval=60")
            if report.risk_level == "low":
                report.risk_level = "low"

        # 5. OOB 检查
        recommendations.append("OOB: 建议自建 interactsh-server, 避免用 oast.fun (可被关联)")

        report.risks = risks
        report.recommendations = recommendations

        if not risks:
            report.risk_level = "low"
            recommendations.append("当前配置较安全, 持续监控")

        return report

    # ============================================================
    #                  工具方法
    # ============================================================

    def _rotate_ua(self) -> str:
        """轮换 User-Agent"""
        new_ua = random.choice(USER_AGENTS)
        while new_ua == self._current_ua and len(USER_AGENTS) > 1:
            new_ua = random.choice(USER_AGENTS)
        self._current_ua = new_ua
        return new_ua

    @staticmethod
    def generate_fake_xff() -> str:
        """
        生成假 X-Forwarded-For (混淆源 IP).

        注意: 这不是真正的 IP 隐藏, 只是增加混淆.
        某些 WAF 会信任 XFF 头.
        """
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    @staticmethod
    def get_safe_oob_domains() -> List[str]:
        """
        返回推荐的 OOB 域名策略.

        公共 OOB (oast.fun) 可以被蓝队监控:
        - 蓝队可能在 DNS 日志里搜索 *.oast.fun
        - 发现后可以关联攻击者的其它活动

        自建 OOB 更安全:
        """
        return [
            "自建 interactsh-server (Docker: projectdiscovery/interactsh-server)",
            "自建 DNS + HTTP 回调服务器 (用无关域名注册)",
            "Burp Collaborator (商业版自带)",
            "避免使用: oast.fun / oast.live / oast.site (公共, 可被监控)",
        ]
