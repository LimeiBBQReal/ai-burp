"""
AIBurp - AI 驱动的渗透测试框架统一入口

核心理念: AI 做决策，工具做执行

使用方式:
    from aiburp import AIBurp
    
    with AIBurp(project="target") as burp:
        # 1. 观察: 访问页面
        view = burp.see("https://target.com/login")
        
        # 2. 操作: 填表
        burp.fill("input[name='username']", "admin")
        burp.fill("input[name='password']", "test")
        burp.click("button[type='submit']")
        
        # 3. 分析: 深度分析参数 (赏金猎人思维)
        for req in burp.traffic.recent(10):
            analysis = burp.analyzer.deep_analyze(req)
            print(analysis.hunter_summary)
        
        # 4. 测试: 基于分析结果测试
        result = burp.repeater.test_sqli(req, "id")

Requirements:
- 18.1: 统一访问 browser, interceptor, repeater, intruder, history
- 18.2: 项目名称创建项目特定数据目录
- 18.3: 代理方法 see(), click(), fill()
- 18.4: traffic 属性访问 TrafficManager
- 18.5: auth 属性访问 AuthManager
- 18.6: oob 属性访问 OOBManager
- 18.7: plugins 属性访问 PluginManager
- 18.8: pocs 属性访问 POCManager
- 18.9: 支持上下文管理器 (with 语句)
- 18.10: close() 清理所有资源
"""

from pathlib import Path
from typing import Optional, Any

from ..core.models import PageView
from ..core.history import History
from ..core.repeater import Repeater
from ..core.intruder import Intruder
from ..core.traffic_manager import TrafficManager
from ..core.auth_manager import AuthManager
from ..core.oob import OOBManager
from ..core.param_analyzer import ParamAnalyzer
from ..core.traffic_diff import TrafficDiff
from ..core.asset_graph import AssetGraph
from ..core.ai_helper import AIHelper
# from . import get_plugin_manager, PluginManager  # TODO: 未实现
# from ..pocs.poc_manager import POCManager  # 直接从 pocs 导入


class AIBurp:
    """
    AI-Burp 统一入口
    
    整合所有模块，提供 AI 友好的接口。
    
    核心模块:
    - browser: 浏览器交互 (BrowserBurp)
    - interceptor: 流量拦截 (Proxy)
    - repeater: 请求重放 (Repeater)
    - intruder: 批量攻击 (Intruder)
    - history: 历史记录 (History)
    
    分析模块:
    - analyzer: 参数深度分析 (ParamAnalyzer)
    - diff: 历史流量对比 (TrafficDiff)
    - ai_helper: AI 决策辅助 (AIHelper)
    
    辅助模块:
    - auth: 认证管理 (AuthManager)
    - oob: 外带检测 (OOBManager)
    - plugins: 插件系统 (PluginManager)
    - pocs: POC 库 (POCManager)
    - assets: 资产图谱 (AssetGraph)
    
    Attributes:
        project: 项目名称
        data_dir: 项目数据目录
        headless: 是否无头模式
    """
    
    def __init__(
        self,
        project: str = "default",
        headless: bool = True,
        proxy_port: int = 8080,
        use_proxy: bool = True,
    ):
        """
        初始化 AI-Burp
        
        Args:
            project: 项目名称，用于数据隔离
            headless: 是否无头模式 (默认 True)
            proxy_port: 代理端口 (默认 8080)
            use_proxy: 是否使用代理拦截流量 (默认 True)
        """
        self.project = project
        self.headless = headless
        self.proxy_port = proxy_port
        self.use_proxy = use_proxy
        
        # 项目数据目录
        self.data_dir = Path.home() / ".aiburp" / project
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # 核心模块
        self.history = History(project)
        self.repeater = Repeater(history=self.history)
        self.intruder = Intruder(history=self.history)
        
        # 浏览器模块 (延迟初始化)
        self._browser = None
        
        # 分析模块 (核心!)
        self.analyzer = ParamAnalyzer(history=self.history)
        self.diff = TrafficDiff(history=self.history)
        self.ai_helper = AIHelper()
        
        # 辅助模块
        self._auth = None
        self._oob = None
        self._plugins = None
        self._pocs = None
        self._assets = None
        self._traffic = None
    
    # ==================== 延迟初始化属性 ====================
    
    @property
    def browser(self):
        """
        获取浏览器模块 (延迟初始化)
        
        Returns:
            BrowserBurp: 浏览器交互模块
        """
        if self._browser is None:
            from .browser import BrowserBurp
            self._browser = BrowserBurp(
                project=self.project,
                headless=self.headless,
                history=self.history,
                proxy_port=self.proxy_port,
                use_proxy=self.use_proxy,
            )
        return self._browser
    
    @property
    def interceptor(self):
        """
        获取拦截器 (通过浏览器的代理)
        
        Returns:
            Proxy: 流量拦截器
        """
        return self.browser.interceptor
    
    @property
    def traffic(self) -> TrafficManager:
        """
        获取流量管理器
        
        Returns:
            TrafficManager: 流量查询管理器
        
        Requirements: 18.4
        """
        if self._traffic is None:
            self._traffic = TrafficManager(self.history)
        return self._traffic
    
    @property
    def auth(self) -> AuthManager:
        """
        获取认证管理器
        
        Returns:
            AuthManager: 认证管理器
        
        Requirements: 18.5
        """
        if self._auth is None:
            self._auth = AuthManager(data_dir=self.data_dir)
        return self._auth
    
    @property
    def oob(self) -> OOBManager:
        """
        获取 OOB 外带检测管理器
        
        Returns:
            OOBManager: OOB 管理器
        
        Requirements: 18.6
        """
        if self._oob is None:
            self._oob = OOBManager()
        return self._oob
    
    @property
    def plugins(self):
        """
        获取插件管理器
        
        Returns:
            PluginManager: 插件管理器
        
        Requirements: 18.7
        """
        # TODO: PluginManager 未实现
        return None
    
    @property
    def pocs(self):
        """
        获取 POC 管理器
        
        Returns:
            POCManager: POC 管理器
        
        Requirements: 18.8
        """
        if self._pocs is None:
            from ..pocs import POCManager
            self._pocs = POCManager()
        return self._pocs
    
    @property
    def assets(self) -> AssetGraph:
        """
        获取资产图谱
        
        Returns:
            AssetGraph: 资产关联图谱
        """
        if self._assets is None:
            self._assets = AssetGraph(self.history)
        return self._assets
    
    # ==================== 代理方法 (浏览器操作) ====================
    
    def see(self, url: str, wait_until: str = "networkidle") -> PageView:
        """
        访问页面，返回 PageView
        
        代理到 BrowserBurp.see()
        
        Args:
            url: 要访问的 URL
            wait_until: 等待条件 (networkidle, load, domcontentloaded)
        
        Returns:
            PageView: 包含截图和 DOM 结构的页面视图
        
        Requirements: 18.3
        """
        return self.browser.see(url, wait_until=wait_until)
    
    def click(self, selector: str, wait_after: bool = True) -> PageView:
        """
        点击元素
        
        代理到 BrowserBurp.click()
        
        Args:
            selector: CSS 选择器
            wait_after: 点击后是否等待网络空闲
        
        Returns:
            PageView: 更新后的页面视图
        
        Requirements: 18.3
        """
        return self.browser.click(selector, wait_after=wait_after)
    
    def fill(self, selector: str, value: str) -> None:
        """
        填充输入框
        
        代理到 BrowserBurp.fill()
        
        Args:
            selector: CSS 选择器
            value: 要填充的值
        
        Requirements: 18.3
        """
        return self.browser.fill(selector, value)
    
    def submit(self, form_selector: Optional[str] = None) -> PageView:
        """
        提交表单
        
        代理到 BrowserBurp.submit()
        
        Args:
            form_selector: 表单选择器 (可选)
        
        Returns:
            PageView: 更新后的页面视图
        """
        return self.browser.submit(form_selector)
    
    def screenshot(self, full_page: bool = False) -> str:
        """
        获取截图 (base64 PNG)
        
        代理到 BrowserBurp.screenshot()
        
        Args:
            full_page: 是否截取整个页面
        
        Returns:
            str: base64 编码的 PNG 图片
        """
        return self.browser.screenshot(full_page=full_page)
    
    def eval(self, js_code: str) -> Any:
        """
        执行 JavaScript
        
        代理到 BrowserBurp.eval()
        
        Args:
            js_code: JavaScript 代码
        
        Returns:
            Any: JavaScript 执行结果
        """
        return self.browser.eval(js_code)
    
    # ==================== 资源清理 ====================
    
    def close(self):
        """
        关闭所有资源
        
        清理:
        - 浏览器和代理
        - OOB 连接
        
        Requirements: 18.10
        """
        # 关闭浏览器
        if self._browser is not None:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None
        
        # 关闭 OOB
        if self._oob is not None:
            try:
                self._oob.close()
            except Exception:
                pass
            self._oob = None
    
    # ==================== 上下文管理器 ====================
    
    def __enter__(self) -> "AIBurp":
        """
        上下文管理器入口
        
        Requirements: 18.9
        """
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        上下文管理器出口
        
        Requirements: 18.9
        """
        self.close()
    
    def __del__(self):
        """析构函数"""
        self.close()
    
    # ==================== 状态查询 ====================
    
    def is_browser_initialized(self) -> bool:
        """浏览器是否已初始化"""
        return self._browser is not None and self._browser.is_initialized()
    
    def to_dict(self) -> dict:
        """
        转为字典 (给 AI 看)
        
        Returns:
            dict: 包含当前状态的字典
        """
        return {
            "project": self.project,
            "data_dir": str(self.data_dir),
            "headless": self.headless,
            "proxy_port": self.proxy_port,
            "use_proxy": self.use_proxy,
            "browser_initialized": self.is_browser_initialized(),
            "history_count": self.history.count() if hasattr(self.history, 'count') else 0,
            "modules": {
                "browser": self._browser is not None,
                "auth": self._auth is not None,
                "oob": self._oob is not None,
                "plugins": self._plugins is not None,
                "pocs": self._pocs is not None,
                "assets": self._assets is not None,
            }
        }
    
    def __repr__(self) -> str:
        return f"AIBurp(project='{self.project}', headless={self.headless})"
