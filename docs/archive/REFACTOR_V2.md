# AI-Burp v2 重构设计文档

## 1. 背景与问题

### 1.1 当前痛点

1. **AI 无法"看到"页面** - 只能发 HTTP 请求，不知道页面有哪些按钮、表单、交互元素
2. **AI 无法"点击"元素** - 只能构造 HTTP 请求，无法模拟真实用户操作，动态 JS 渲染内容无法获取
3. **脚本臃肿问题** - AI 写的脚本被复制到 Docker 容器，导致镜像越来越大
4. **流量拦截不完整** - 当前是主动发请求模式，不是拦截真实流量
5. **模块重复** - proxy.py + mitm_proxy.py + mitm_proxy_v2.py 功能重叠
6. **硬编码问题** - 部分文件有目标硬编码，缺乏模块化设计

### 1.2 核心需求

> AI 能看到页面 → AI 能点击元素 → 所有交互自动拦截 → AI 决策测试

像 Burp Suite 一样:
- **拦截 (Intercept)**: 捕获所有流量
- **修改 (Modify)**: 修改请求/响应
- **重放 (Repeater)**: 重放并对比
- **批量 (Intruder)**: 批量 fuzz 测试

## 2. 新架构设计

### 2.1 架构图

```
┌─────────────────────────────────────────────────────────────────┐
│                        AI 决策中心                               │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  1. 看到页面 (screenshot + DOM)                          │   │
│  │  2. 看到流量 (拦截的请求/响应)                            │   │
│  │  3. 做出决策 (点击/填表/修改请求/重放/测试)               │   │
│  │  4. 看到结果 (响应变化/错误信息/时间差异)                 │   │
│  │  5. 继续决策...                                          │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐   ┌───────────────┐   ┌───────────────┐
│   Browser     │   │  Interceptor  │   │   Repeater    │
│   (看+操作)    │   │  (拦截+修改)   │   │  (重放+测试)   │
├───────────────┤   ├───────────────┤   ├───────────────┤
│ see()         │   │ intercept()   │   │ send()        │
│ click()       │   │ modify()      │   │ fuzz()        │
│ fill()        │   │ forward()     │   │ compare()     │
│ screenshot()  │   │ drop()        │   │ test()        │
└───────────────┘   └───────────────┘   └───────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                    ┌───────────────┐
                    │   History     │
                    │  (所有流量)    │
                    └───────────────┘
```

### 2.2 目录结构

```
aiburp/
├── __init__.py           # 统一入口，简化导出
├── browser.py            # 🆕 浏览器交互模块
├── interceptor.py        # 🆕 统一拦截器 (合并 proxy/mitm)
├── repeater.py           # 重放器 (从 core/repeater.py 提升)
├── intruder.py           # 批量攻击 (从 core/intruder.py 提升)
├── history.py            # 历史记录 (从 core/history.py 提升)
├── detector.py           # 漏洞检测 (合并 detectors.py)
├── payloads.py           # Payload 加载 (保留)
├── cli.py                # 精简 CLI
├── core/
│   └── models.py         # 数据结构
└── deprecated/           # 🆕 废弃模块 (保留但不使用)
    ├── proxy.py
    ├── mitm_proxy.py
    ├── mitm_proxy_v2.py
    └── auto_crawler.py
```

## 3. 核心模块设计

### 3.1 Browser 模块 (browser.py)

AI 的"眼睛"和"手"，基于 Playwright。

```python
class BrowserBurp:
    """AI 可视化交互模块"""
    
    def __init__(self, project: str, headless: bool = True):
        """初始化浏览器，自动配置代理"""
        
    def see(self, url: str) -> PageView:
        """
        访问页面，返回截图和 DOM 结构
        
        Returns:
            PageView: {
                screenshot: str (base64),
                title: str,
                url: str,
                forms: List[FormInfo],
                links: List[LinkInfo],
                buttons: List[ButtonInfo],
                inputs: List[InputInfo]
            }
        """
        
    def click(self, selector: str) -> PageView:
        """点击元素，返回新的页面状态"""
        
    def fill(self, selector: str, value: str) -> None:
        """填充输入框"""
        
    def submit(self, form_selector: str = None) -> PageView:
        """提交表单"""
        
    def screenshot(self) -> str:
        """获取当前截图 (base64)"""
        
    def eval(self, js_code: str) -> Any:
        """在页面执行 JavaScript"""
        
    def close(self) -> None:
        """关闭浏览器"""
```

**PageView 数据结构**:

```python
@dataclass
class PageView:
    screenshot: str  # base64 encoded PNG
    title: str
    url: str
    forms: List[FormInfo]
    links: List[LinkInfo]
    buttons: List[ButtonInfo]
    inputs: List[InputInfo]
    
@dataclass
class FormInfo:
    action: str
    method: str
    selector: str
    inputs: List[InputInfo]
    submit_button: Optional[ButtonInfo]
    
@dataclass
class InputInfo:
    name: str
    type: str  # text, password, email, hidden, etc.
    selector: str
    value: Optional[str]
    placeholder: Optional[str]
```

### 3.2 Interceptor 模块 (interceptor.py)

统一的流量拦截器，合并现有的 proxy/mitm 功能。

```python
class Interceptor:
    """流量拦截器"""
    
    def __init__(self, port: int = 8080):
        """启动代理服务器"""
        
    def start(self) -> None:
        """启动拦截"""
        
    def stop(self) -> None:
        """停止拦截"""
        
    @property
    def traffic(self) -> TrafficManager:
        """获取流量管理器"""
        
class TrafficManager:
    """流量管理"""
    
    def recent(self, n: int = 10) -> List[Request]:
        """获取最近 n 条请求"""
        
    def find(self, **filters) -> Optional[Request]:
        """查找请求 (by path, method, host, etc.)"""
        
    def filter(self, **filters) -> List[Request]:
        """过滤请求"""
        
    def clear(self) -> None:
        """清空历史"""
```

### 3.3 Repeater 模块 (repeater.py)

请求重放和测试 (已有实现，需提升到顶层)。

```python
class Repeater:
    """请求重放器"""
    
    def send(self, request: Request, modify: dict = None) -> Response:
        """发送请求，可选修改参数"""
        
    def compare(self, request: Request, payloads: List[str], param: str) -> List[CompareResult]:
        """对比测试，用不同 payload 发送请求并对比响应"""
        
    def fuzz(self, request: Request, param: str, payloads: List[str]) -> List[FuzzResult]:
        """Fuzz 测试"""
        
    def test_sqli(self, request: Request, param: str) -> VulnResult:
        """SQL 注入测试"""
        
    def test_xss(self, request: Request, param: str) -> VulnResult:
        """XSS 测试"""
```

### 3.4 统一入口 (__init__.py)

```python
from .browser import BrowserBurp, PageView
from .interceptor import Interceptor, TrafficManager
from .repeater import Repeater
from .intruder import Intruder
from .history import History
from .detector import Detector
from .payloads import Payloads

class AIBurp:
    """AI-Burp 统一入口"""
    
    def __init__(self, project: str, headless: bool = True):
        self.browser = BrowserBurp(project, headless)
        self.interceptor = Interceptor()
        self.repeater = Repeater()
        self.intruder = Intruder()
        self.history = History(project)
        
    @property
    def traffic(self) -> TrafficManager:
        return self.interceptor.traffic
        
    def see(self, url: str) -> PageView:
        return self.browser.see(url)
        
    def click(self, selector: str) -> PageView:
        return self.browser.click(selector)
        
    def fill(self, selector: str, value: str) -> None:
        return self.browser.fill(selector, value)
```

## 4. AI 决策适配

### 4.1 AI 工作流程

```python
from aiburp import AIBurp

# 初始化
burp = AIBurp(project="target")

# Step 1: AI 看到页面
view = burp.see("https://target.com/login")
# AI 收到: screenshot (图片), forms (表单列表), links (链接列表)

# Step 2: AI 决定操作
burp.fill("#username", "admin")
burp.fill("#password", "test123")
view = burp.click("button[type=submit]")

# Step 3: AI 看到流量
traffic = burp.traffic.recent(5)
# AI 收到: 最近 5 条请求的详情

# Step 4: AI 选择测试
login_req = burp.traffic.find(path="/api/login")
result = burp.repeater.test_sqli(login_req, param="password")

# Step 5: AI 看到结果，继续决策
if result.vulnerable:
    burp.history.mark_vuln(login_req, "SQL Injection", result)
```

### 4.2 AI 输出格式

为了让 AI 能理解页面，`see()` 返回的 DOM 需要简化：

```json
{
  "screenshot": "base64...",
  "title": "Login - Target",
  "url": "https://target.com/login",
  "forms": [
    {
      "action": "/api/login",
      "method": "POST",
      "selector": "form#login-form",
      "inputs": [
        {"name": "username", "type": "text", "selector": "#username"},
        {"name": "password", "type": "password", "selector": "#password"}
      ],
      "submit": {"text": "Login", "selector": "button[type=submit]"}
    }
  ],
  "links": [
    {"text": "Forgot Password", "href": "/forgot", "selector": "a.forgot"},
    {"text": "Register", "href": "/register", "selector": "a.register"}
  ],
  "buttons": [
    {"text": "Login", "selector": "button[type=submit]"},
    {"text": "Help", "selector": "#help-btn"}
  ]
}
```

### 4.3 AI 决策辅助

```python
class AIHelper:
    """辅助 AI 决策"""
    
    @staticmethod
    def suggest_tests(view: PageView) -> List[str]:
        """根据页面结构建议测试点"""
        
    @staticmethod
    def analyze_response(response: Response) -> Dict:
        """分析响应，提取关键信息"""
```

## 5. 实现计划

### Phase 1: Browser 模块 (优先级最高)
- [ ] 实现 `BrowserBurp` 类
- [ ] 实现 `see()`, `click()`, `fill()` 方法
- [ ] 实现 DOM 简化输出
- [ ] 集成 Playwright

### Phase 2: Interceptor 模块
- [ ] 合并 proxy.py, mitm_proxy.py, mitm_proxy_v2.py
- [ ] 实现统一的 `Interceptor` 类
- [ ] 实现 `TrafficManager`
- [ ] 浏览器自动配置代理

### Phase 3: Repeater 模块
- [ ] 从 core/repeater.py 提升
- [ ] 增加 `compare()`, `fuzz()` 方法
- [ ] 增加 `test_sqli()`, `test_xss()` 快捷方法

### Phase 4: 统一入口
- [ ] 实现 `AIBurp` 统一类
- [ ] 简化 `__init__.py` 导出
- [ ] 更新 CLI

### Phase 5: 清理
- [ ] 移动废弃模块到 `deprecated/`
- [ ] 删除硬编码
- [ ] 更新文档

## 6. 依赖更新

```
# requirements.txt 新增
playwright>=1.40.0
```

安装 Playwright:
```bash
pip install playwright
playwright install chromium
```

## 7. 脚本存放规范

### 问题
AI 写的脚本被复制到 Docker 容器内，导致镜像臃肿。

### 解决方案
```
E:\mcp_workspace\           # 挂载到 /data
├── scripts\                # AI 生成的脚本放这里
│   ├── heritage_test.py
│   └── ...
├── results\                # 测试结果
└── ...

# AI 执行脚本
docker exec src-toolbox sh -c "python3 /data/scripts/xxx.py"
```

### 规范
1. AI 生成的脚本必须放在 `/data/scripts/`
2. 不要用 `docker cp` 复制脚本到容器
3. 结果输出到 `/data/results/`

## 8. 下一步

1. ✅ 确认此设计文档
2. 开始 Phase 1: 实现 Browser 模块
3. 测试 `see()` + `click()` 功能
4. 继续其他 Phase
