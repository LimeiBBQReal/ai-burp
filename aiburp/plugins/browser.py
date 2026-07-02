"""
AIBURP Browser - 浏览器交互模块

基于 Playwright 实现，AI 的"眼睛"和"手"

核心功能:
- 访问页面并提取 PageView (截图 + DOM 结构)
- 点击、填充、提交等页面操作
- 自动通过代理拦截流量
- 执行 JavaScript

使用方式:
    browser = BrowserBurp(project="target", headless=True)
    
    # 访问页面
    view = browser.see("https://example.com")
    print(view.forms)  # 表单列表
    print(view.links)  # 链接列表
    
    # 操作页面
    browser.fill("#username", "admin")
    browser.fill("#password", "password")
    view = browser.click("#login-btn")
    
    # 截图
    screenshot = browser.screenshot()
    
    # 执行 JS
    result = browser.eval("document.title")
    
    # 清理
    browser.close()
"""

import base64
import time
from typing import Any, Optional, List
from pathlib import Path

from ..core.models import (
    PageView, FormInfo, InputInfo, LinkInfo, ButtonInfo
)
from ..core.history import History
from ..core.proxy import Proxy, ProxyConfig


class BrowserBurp:
    """
    基于 Playwright 的浏览器交互模块
    
    AI 的"眼睛"和"手"，用于:
    - 观察页面 (see)
    - 操作元素 (click, fill, submit)
    - 截图 (screenshot)
    - 执行 JS (eval)
    
    所有流量自动通过 Proxy 拦截并记录到 History
    """
    
    def __init__(
        self,
        project: str = "default",
        headless: bool = True,
        history: Optional[History] = None,
        proxy_port: int = 8080,
        use_proxy: bool = True,
    ):
        """
        初始化浏览器
        
        Args:
            project: 项目名称，用于数据隔离
            headless: 是否无头模式 (默认 True)
            history: History 实例 (可选，不传则自动创建)
            proxy_port: 代理端口 (默认 8080)
            use_proxy: 是否使用代理拦截流量 (默认 True)
        """
        self.project = project
        self.headless = headless
        self.use_proxy = use_proxy
        self.proxy_port = proxy_port
        
        # History
        self.history = history or History(project)
        
        # Proxy (Interceptor)
        self.proxy: Optional[Proxy] = None
        if use_proxy:
            config = ProxyConfig(port=proxy_port)
            self.proxy = Proxy(self.history, config)
        
        # Playwright 组件
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        
        # 状态
        self._initialized = False
    
    def _ensure_initialized(self):
        """确保浏览器已初始化"""
        if self._initialized:
            return
        
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise ImportError(
                "Playwright is required for BrowserBurp. "
                "Install it with: pip install playwright && playwright install chromium"
            )
        
        # 启动代理
        if self.proxy:
            self.proxy.start()
            time.sleep(0.5)  # 等待代理启动
        
        # 启动 Playwright
        self._playwright = sync_playwright().start()
        
        # 启动浏览器
        launch_options = {
            "headless": self.headless,
        }
        
        # 配置代理
        if self.proxy:
            launch_options["proxy"] = {
                "server": f"http://127.0.0.1:{self.proxy_port}"
            }
        
        self._browser = self._playwright.chromium.launch(**launch_options)
        
        # 创建上下文 (忽略 HTTPS 错误)
        self._context = self._browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1920, "height": 1080},
        )
        
        # 创建页面
        self._page = self._context.new_page()
        
        self._initialized = True
    
    @property
    def interceptor(self) -> Optional[Proxy]:
        """获取拦截器 (Proxy)"""
        return self.proxy
    
    @property
    def page(self):
        """获取 Playwright Page 对象"""
        self._ensure_initialized()
        return self._page
    
    # ==================== 页面观察 ====================
    
    def see(self, url: str, wait_until: str = "networkidle") -> PageView:
        """
        访问页面，返回 PageView
        
        Args:
            url: 要访问的 URL
            wait_until: 等待条件 (networkidle, load, domcontentloaded)
        
        Returns:
            PageView: 包含截图和 DOM 结构的页面视图
        """
        self._ensure_initialized()
        
        # 访问页面
        self._page.goto(url, wait_until=wait_until)
        
        # 提取页面视图
        return self._extract_page_view()
    
    def _extract_page_view(self) -> PageView:
        """提取页面视图"""
        forms = self._extract_forms()
        links = self._extract_links()
        buttons = self._extract_buttons()
        inputs = self._extract_inputs()
        
        return PageView(
            screenshot=self.screenshot(),
            title=self._page.title(),
            url=self._page.url,
            forms=forms,
            links=links,
            buttons=buttons,
            inputs=inputs,
        )
    
    def _extract_forms(self) -> List[FormInfo]:
        """提取所有表单"""
        forms = []
        
        form_elements = self._page.query_selector_all("form")
        
        for i, form in enumerate(form_elements):
            # 生成唯一选择器
            form_id = form.get_attribute("id")
            form_name = form.get_attribute("name")
            form_class = form.get_attribute("class")
            
            if form_id:
                selector = f"form#{form_id}"
            elif form_name:
                selector = f"form[name='{form_name}']"
            elif form_class:
                first_class = form_class.split()[0] if form_class else ""
                selector = f"form.{first_class}" if first_class else f"form:nth-of-type({i+1})"
            else:
                selector = f"form:nth-of-type({i+1})"
            
            # 提取表单属性
            action = form.get_attribute("action") or ""
            method = (form.get_attribute("method") or "GET").upper()
            
            # 提取表单内的输入框
            form_inputs = []
            input_elements = form.query_selector_all("input, textarea, select")
            
            for j, inp in enumerate(input_elements):
                inp_info = self._extract_input_info(inp, j, selector)
                if inp_info:
                    form_inputs.append(inp_info)
            
            # 提取提交按钮
            submit_btn = None
            submit_element = form.query_selector("button[type='submit'], input[type='submit']")
            if submit_element:
                btn_text = submit_element.inner_text() if submit_element.inner_text() else submit_element.get_attribute("value") or "Submit"
                btn_id = submit_element.get_attribute("id")
                if btn_id:
                    btn_selector = f"#{btn_id}"
                else:
                    btn_selector = f"{selector} button[type='submit'], {selector} input[type='submit']"
                
                submit_btn = ButtonInfo(
                    text=btn_text.strip(),
                    selector=btn_selector,
                    type="submit"
                )
            
            forms.append(FormInfo(
                action=action,
                method=method,
                selector=selector,
                inputs=form_inputs,
                submit_button=submit_btn,
            ))
        
        return forms
    
    def _extract_input_info(self, element, index: int, parent_selector: str = "") -> Optional[InputInfo]:
        """提取单个输入框信息"""
        tag_name = element.evaluate("el => el.tagName.toLowerCase()")
        
        # 获取属性
        inp_id = element.get_attribute("id")
        inp_name = element.get_attribute("name")
        inp_type = element.get_attribute("type") or "text"
        inp_value = element.get_attribute("value")
        inp_placeholder = element.get_attribute("placeholder")
        inp_class = element.get_attribute("class")
        
        # 跳过隐藏和提交类型
        if inp_type in ["hidden", "submit", "button", "reset"]:
            return None
        
        # 生成选择器
        if inp_id:
            selector = f"#{inp_id}"
        elif inp_name:
            if parent_selector:
                selector = f"{parent_selector} [name='{inp_name}']"
            else:
                selector = f"[name='{inp_name}']"
        elif inp_class:
            first_class = inp_class.split()[0] if inp_class else ""
            if first_class and parent_selector:
                selector = f"{parent_selector} {tag_name}.{first_class}"
            elif first_class:
                selector = f"{tag_name}.{first_class}"
            else:
                selector = f"{parent_selector} {tag_name}:nth-of-type({index+1})" if parent_selector else f"{tag_name}:nth-of-type({index+1})"
        else:
            selector = f"{parent_selector} {tag_name}:nth-of-type({index+1})" if parent_selector else f"{tag_name}:nth-of-type({index+1})"
        
        return InputInfo(
            name=inp_name or "",
            type=inp_type,
            selector=selector,
            value=inp_value,
            placeholder=inp_placeholder,
        )
    
    def _extract_links(self) -> List[LinkInfo]:
        """提取所有链接"""
        links = []
        
        link_elements = self._page.query_selector_all("a[href]")
        
        for i, link in enumerate(link_elements):
            href = link.get_attribute("href") or ""
            text = link.inner_text().strip()
            
            # 跳过空链接和锚点
            if not href or href == "#" or href.startswith("javascript:"):
                continue
            
            # 生成选择器
            link_id = link.get_attribute("id")
            link_class = link.get_attribute("class")
            
            if link_id:
                selector = f"a#{link_id}"
            elif text and len(text) < 50:
                # 使用文本作为选择器 (如果文本不太长)
                selector = f"a:has-text('{text[:30]}')"
            elif link_class:
                first_class = link_class.split()[0] if link_class else ""
                selector = f"a.{first_class}" if first_class else f"a:nth-of-type({i+1})"
            else:
                selector = f"a[href='{href}']" if len(href) < 100 else f"a:nth-of-type({i+1})"
            
            links.append(LinkInfo(
                text=text[:100] if text else "",  # 截断长文本
                href=href,
                selector=selector,
            ))
        
        return links
    
    def _extract_buttons(self) -> List[ButtonInfo]:
        """提取所有按钮 (不在表单内的)"""
        buttons = []
        
        # 查找不在表单内的按钮
        button_elements = self._page.query_selector_all("button:not(form button), input[type='button']:not(form input)")
        
        for i, btn in enumerate(button_elements):
            tag_name = btn.evaluate("el => el.tagName.toLowerCase()")
            
            if tag_name == "button":
                text = btn.inner_text().strip()
            else:
                text = btn.get_attribute("value") or ""
            
            btn_type = btn.get_attribute("type") or "button"
            btn_id = btn.get_attribute("id")
            btn_class = btn.get_attribute("class")
            
            # 生成选择器
            if btn_id:
                selector = f"#{btn_id}"
            elif text and len(text) < 30:
                selector = f"button:has-text('{text}')"
            elif btn_class:
                first_class = btn_class.split()[0] if btn_class else ""
                selector = f"button.{first_class}" if first_class else f"button:nth-of-type({i+1})"
            else:
                selector = f"button:nth-of-type({i+1})"
            
            buttons.append(ButtonInfo(
                text=text[:50] if text else "",
                selector=selector,
                type=btn_type,
            ))
        
        return buttons
    
    def _extract_inputs(self) -> List[InputInfo]:
        """提取所有独立输入框 (不在表单内的)"""
        inputs = []
        
        # 查找不在表单内的输入框
        input_elements = self._page.query_selector_all(
            "input:not(form input):not([type='hidden']):not([type='submit']):not([type='button']):not([type='reset']), "
            "textarea:not(form textarea), "
            "select:not(form select)"
        )
        
        for i, inp in enumerate(input_elements):
            inp_info = self._extract_input_info(inp, i)
            if inp_info:
                inputs.append(inp_info)
        
        return inputs

    
    # ==================== 页面操作 ====================
    
    def click(self, selector: str, wait_after: bool = True) -> PageView:
        """
        点击元素
        
        Args:
            selector: CSS 选择器
            wait_after: 点击后是否等待网络空闲
        
        Returns:
            PageView: 更新后的页面视图
        """
        self._ensure_initialized()
        
        self._page.click(selector)
        
        if wait_after:
            self._page.wait_for_load_state("networkidle")
        
        return self._extract_page_view()
    
    def fill(self, selector: str, value: str) -> None:
        """
        填充输入框
        
        Args:
            selector: CSS 选择器
            value: 要填充的值
        """
        self._ensure_initialized()
        
        self._page.fill(selector, value)
    
    def submit(self, form_selector: Optional[str] = None) -> PageView:
        """
        提交表单
        
        Args:
            form_selector: 表单选择器 (可选，不传则按 Enter)
        
        Returns:
            PageView: 更新后的页面视图
        """
        self._ensure_initialized()
        
        if form_selector:
            # 在表单内按 Enter
            self._page.locator(form_selector).press("Enter")
        else:
            # 直接按 Enter
            self._page.keyboard.press("Enter")
        
        self._page.wait_for_load_state("networkidle")
        
        return self._extract_page_view()
    
    def screenshot(self, full_page: bool = False) -> str:
        """
        获取截图 (base64 PNG)
        
        Args:
            full_page: 是否截取整个页面
        
        Returns:
            str: base64 编码的 PNG 图片
        """
        self._ensure_initialized()
        
        screenshot_bytes = self._page.screenshot(full_page=full_page)
        return base64.b64encode(screenshot_bytes).decode()
    
    def eval(self, js_code: str) -> Any:
        """
        执行 JavaScript
        
        Args:
            js_code: JavaScript 代码
        
        Returns:
            Any: JavaScript 执行结果
        """
        self._ensure_initialized()
        
        return self._page.evaluate(js_code)
    
    # ==================== 辅助方法 ====================
    
    def wait(self, timeout: int = 1000):
        """
        等待指定时间
        
        Args:
            timeout: 等待时间 (毫秒)
        """
        self._ensure_initialized()
        self._page.wait_for_timeout(timeout)
    
    def wait_for_selector(self, selector: str, timeout: int = 30000) -> bool:
        """
        等待元素出现
        
        Args:
            selector: CSS 选择器
            timeout: 超时时间 (毫秒)
        
        Returns:
            bool: 元素是否出现
        """
        self._ensure_initialized()
        
        try:
            self._page.wait_for_selector(selector, timeout=timeout)
            return True
        except:
            return False
    
    def type(self, selector: str, text: str, delay: int = 50):
        """
        模拟键盘输入 (逐字符)
        
        Args:
            selector: CSS 选择器
            text: 要输入的文本
            delay: 每个字符之间的延迟 (毫秒)
        """
        self._ensure_initialized()
        
        self._page.type(selector, text, delay=delay)
    
    def select(self, selector: str, value: str):
        """
        选择下拉框选项
        
        Args:
            selector: CSS 选择器
            value: 选项值
        """
        self._ensure_initialized()
        
        self._page.select_option(selector, value)
    
    def check(self, selector: str):
        """勾选复选框"""
        self._ensure_initialized()
        self._page.check(selector)
    
    def uncheck(self, selector: str):
        """取消勾选复选框"""
        self._ensure_initialized()
        self._page.uncheck(selector)
    
    def hover(self, selector: str):
        """鼠标悬停"""
        self._ensure_initialized()
        self._page.hover(selector)
    
    def scroll_to(self, selector: str):
        """滚动到元素"""
        self._ensure_initialized()
        self._page.locator(selector).scroll_into_view_if_needed()
    
    def get_text(self, selector: str) -> str:
        """获取元素文本"""
        self._ensure_initialized()
        return self._page.inner_text(selector)
    
    def get_attribute(self, selector: str, attribute: str) -> Optional[str]:
        """获取元素属性"""
        self._ensure_initialized()
        return self._page.get_attribute(selector, attribute)
    
    def is_visible(self, selector: str) -> bool:
        """检查元素是否可见"""
        self._ensure_initialized()
        return self._page.is_visible(selector)
    
    def is_enabled(self, selector: str) -> bool:
        """检查元素是否启用"""
        self._ensure_initialized()
        return self._page.is_enabled(selector)
    
    def get_cookies(self) -> List[dict]:
        """获取所有 cookies"""
        self._ensure_initialized()
        return self._context.cookies()
    
    def set_cookies(self, cookies: List[dict]):
        """设置 cookies"""
        self._ensure_initialized()
        self._context.add_cookies(cookies)
    
    def clear_cookies(self):
        """清除所有 cookies"""
        self._ensure_initialized()
        self._context.clear_cookies()
    
    def go_back(self) -> PageView:
        """后退"""
        self._ensure_initialized()
        self._page.go_back()
        self._page.wait_for_load_state("networkidle")
        return self._extract_page_view()
    
    def go_forward(self) -> PageView:
        """前进"""
        self._ensure_initialized()
        self._page.go_forward()
        self._page.wait_for_load_state("networkidle")
        return self._extract_page_view()
    
    def reload(self) -> PageView:
        """刷新页面"""
        self._ensure_initialized()
        self._page.reload()
        self._page.wait_for_load_state("networkidle")
        return self._extract_page_view()
    
    @property
    def current_url(self) -> str:
        """获取当前 URL"""
        self._ensure_initialized()
        return self._page.url
    
    @property
    def title(self) -> str:
        """获取页面标题"""
        self._ensure_initialized()
        return self._page.title()
    
    # ==================== 资源清理 ====================
    
    def close(self):
        """
        关闭浏览器和代理，释放所有资源
        """
        # 关闭页面
        if self._page:
            try:
                self._page.close()
            except:
                pass
            self._page = None
        
        # 关闭上下文
        if self._context:
            try:
                self._context.close()
            except:
                pass
            self._context = None
        
        # 关闭浏览器
        if self._browser:
            try:
                self._browser.close()
            except:
                pass
            self._browser = None
        
        # 停止 Playwright
        if self._playwright:
            try:
                self._playwright.stop()
            except:
                pass
            self._playwright = None
        
        # 停止代理
        if self.proxy:
            try:
                self.proxy.stop()
            except:
                pass
        
        self._initialized = False
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.close()
    
    def __del__(self):
        """析构函数"""
        self.close()
    
    # ==================== 状态查询 ====================
    
    def is_initialized(self) -> bool:
        """是否已初始化"""
        return self._initialized
    
    def to_dict(self) -> dict:
        """转为字典 (给 AI 看)"""
        return {
            "project": self.project,
            "headless": self.headless,
            "initialized": self._initialized,
            "use_proxy": self.use_proxy,
            "proxy_port": self.proxy_port,
            "current_url": self._page.url if self._page else None,
            "title": self._page.title() if self._page else None,
        }
