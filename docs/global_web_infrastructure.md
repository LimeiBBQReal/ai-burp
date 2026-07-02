# 全球互联网数据基础设施 - 小说素材

> 整理时间: 2024-12-20
> 用途: 小说创作素材储备

---

## 一、核心概念关系图


Chrome用户 --> Chrome UX Report --> HTTP Archive --> BigQuery --> Commonspeak2 --> Assetnote Wordlists --> 安全研究员

简单说:
- Google收集用户访问数据
- HTTP Archive用这些数据爬取网站
- 存入BigQuery供查询
- Assetnote从中提取安全字典
- 安全研究员用字典做渗透测试

---

## 二、各组件详解

### 1. Chrome UX Report (CrUX)

**是什么**: Google官方的真实用户体验数据集

**数据来源**:
- 全球Chrome浏览器用户(同意数据收集的)
- Chrome上报用户访问的网站
- Google汇总统计后发布

**包含内容**:
- 热门网站列表(按访问量排序)
- 性能指标(LCP, FID, CLS)
- 地区分布
- 设备类型(手机/桌面)

**为什么重要**:
这是最权威的热门网站列表,比Alexa Top 1M更准确,因为基于真实用户访问,每月更新,是Google官方数据。

**小说素材点**:
- Google通过Chrome浏览器掌握了全球用户的上网行为
- 这些数据价值连城,是互联网的"上帝视角"
- 任何网站的真实流量,Google都知道


Chrome用户 (数十亿) --> Chrome UX Report --> HTTP Archive --> BigQuery --> Commonspeak2 --> Wordlists
     |                      |                    |              |              |              |
  匿名上报            热门网站列表          WebPageTest爬取    PB级存储      SQL提取        安全字典
                      (800万+)              完整技术数据       Google赞助    Assetnote      免费发布

---

## 二、HTTP Archive (httparchive.org)

### 2.1 是什么
一个非营利项目，从2010年开始定期爬取全球Top网站，记录网页的完整技术数据。
被称为"互联网的X光机"，可以看到整个Web的技术演变。

### 2.2 数据规模
- 网站数量: 800万+ (基于Chrome UX Report)
- 数据量: PB级 (Petabyte，1PB = 1000TB)
- 历史跨度: 2010年至今
- 更新频率: 每月1次

### 2.3 包含的数据类型

| 数据类型 | 具体内容 | 安全研究用途 |
|----------|----------|--------------|
| 请求URL | 完整HTTP请求URL | 提取目录/文件/参数名 |
| 响应头 | Server, X-Powered-By等 | 技术栈识别/指纹 |
| HTML内容 | 页面完整源码 | 提取链接/表单/隐藏参数 |
| JavaScript | 所有加载的JS文件 | 提取API端点/密钥泄露 |
| CSS | 样式表 | CDN识别 |
| 性能数据 | 加载时间/大小 | - |
| 技术检测 | 使用的框架/CMS | 漏洞关联 |
| 第三方资源 | 外部JS/CSS/API | 供应链分析 |

### 2.4 小说素材价值
- 可以追溯任何大型网站10年来的技术演变
- 能发现哪些老旧技术仍在被使用
- 统计全球网站的安全状况
- 发现隐藏的API和敏感路径


Chrome用户 --> CrUX(热门网站列表) --> HTTP Archive --> BigQuery
                                          |
                                    WebPageTest爬虫
                                          |
                                    Commonspeak2查询
                                          |
                                    Assetnote Wordlists
                                          |
                                    安全研究员使用

---

## 二、HTTP Archive (httparchive.org)

### 2.1 是什么
一个非营利项目，从2010年开始定期爬取全球Top网站，记录网页的完整技术数据。
被称为互联网的时光机器。

### 2.2 数据规模
- 800万+ 网站
- PB级数据量
- 2010年至今的历史数据
- 每月更新一次

### 2.3 包含的数据类型

| 数据类型 | 内容 | 安全研究用途 |
|----------|------|--------------|
| 请求URL | 完整的HTTP请求URL | 提取目录/文件/参数 |
| 响应头 | Server, X-Powered-By等 | 技术栈识别 |
| HTML内容 | 页面HTML源码 | 提取链接/表单 |
| JavaScript | 所有加载的JS文件 | 提取API端点 |
| CSS | 样式表 | - |
| 图片/字体 | 资源URL | CDN识别 |
| 性能数据 | 加载时间、大小 | - |
| 技术检测 | 使用的框架/CMS | 指纹识别 |
| 第三方资源 | 外部JS/CSS/API | 供应链分析 |

### 2.4 小说素材价值
- 可以查询任何网站10年来的技术演变
- 知道哪些老旧技术还在被使用
- 发现隐藏的API端点和参数
- 追踪第三方服务的使用情况


Chrome UX Report --> HTTP Archive --> BigQuery --> Commonspeak2 --> Wordlists
   (热门网站)       (爬取数据)      (存储)        (提取)         (字典)
      |                |              |              |              |
   Google           非营利        Google Cloud    Assetnote      安全研究员
   (官方)           (项目)         (赞助)         (工具)          (使用)

---

## 二、Chrome UX Report (CrUX)

### 2.1 定义
Google 官方的真实用户体验数据集，基于全球 Chrome 浏览器用户的匿名访问数据汇总。

### 2.2 数据来源
- 全球数十亿 Chrome 用户 (同意数据收集)
- Chrome 浏览器自动上报访问的网站
- Google 汇总统计后发布

### 2.3 包含内容
| 数据类型 | 说明 |
|----------|------|
| 热门网站列表 | 按真实访问量排序的 800万+ 网站 |
| 性能指标 | LCP, FID, CLS 等 Core Web Vitals |
| 地区分布 | 各国/地区的访问情况 |
| 设备类型 | 手机/桌面/平板比例 |

### 2.4 为什么重要
这是最权威的热门网站列表，比 Alexa Top 1M 更准确：
- 基于真实用户访问 (不是爬虫模拟)
- 每月更新
- Google 官方数据，无法伪造

### 2.5 小说素材价值
> 想象一下：全球数十亿人每天的上网行为，都被一家公司默默记录着。
> 他们知道哪些网站最热门，哪些页面加载最慢，哪些地区的人喜欢访问什么。
> 这不是监控，这是"用户体验优化"。

---

## 三、WebPageTest

### 3.1 定义
开源的网页性能测试工具，最初由 AOL 开发，后来开源。

### 3.2 核心能力
- 使用真实浏览器 (Chrome/Firefox) 加载网页
- 记录完整的加载过程 (瀑布图)
- 捕获所有 HTTP 请求/响应
- 截图、录制视频
- 测量各种性能指标

### 3.3 与普通爬虫的区别
| 对比项 | 普通爬虫 (requests/scrapy) | WebPageTest |
|--------|---------------------------|-------------|
| 渲染方式 | 只获取 HTML | 真实浏览器渲染 |
| JavaScript | 不执行 | 完整执行 |
| 动态内容 | 看不到 | 完整捕获 |
| AJAX 请求 | 无法获取 | 全部记录 |
| 资源列表 | 不完整 | 完整 |

### 3.4 小说素材价值
> 普通爬虫只能看到网页的骨架，而 WebPageTest 能看到网页的灵魂。
> 它像一个真实的用户一样浏览网页，记录下每一个细节：
> 哪些 JavaScript 被执行了，哪些 API 被调用了，哪些数据被传输了。

---


Chrome用户 --> Chrome UX Report --> HTTP Archive --> BigQuery --> Commonspeak2 --> Assetnote Wordlists --> 安全研究员

---

## 二、HTTP Archive (httparchive.org)

### 2.1 是什么
非营利项目，从2010年开始定期爬取全球Top网站，记录网页完整技术数据。

### 2.2 数据规模
- 800万+ 网站
- PB级数据量
- 2010年至今历史数据
- 每月更新

### 2.3 包含的数据类型

| 数据类型 | 内容 | 安全用途 |
|----------|------|----------|
| 请求URL | 完整HTTP请求URL | 提取目录/文件/参数 |
| 响应头 | Server, X-Powered-By等 | 技术栈识别 |
| HTML内容 | 页面HTML源码 | 提取链接/表单 |
| JavaScript | 所有加载的JS文件 | 提取API端点 |
| CSS | 样式表 | - |
| 图片/字体 | 资源URL | CDN识别 |
| 性能数据 | 加载时间、大小 | - |
| 技术检测 | 使用的框架/CMS | 指纹识别 |
| 第三方资源 | 外部JS/CSS/API | 供应链分析 |

---

## 三、Chrome UX Report (CrUX)

### 3.1 是什么
Google官方的真实用户体验数据集，基于Chrome浏览器收集。

### 3.2 数据来源流程
全球Chrome用户(同意数据收集) --> Chrome浏览器上报访问的网站 --> Google汇总统计 --> 发布CrUX数据集

### 3.3 包含内容
- 热门网站列表(按访问量排序)
- 性能指标(LCP, FID, CLS等)
- 地区分布
- 设备类型(手机/桌面比例)

### 3.4 为什么重要
这是最权威的热门网站列表，比Alexa Top 1M更准确：
- 基于真实用户访问
- 每月更新
- Google官方数据

---

## 四、WebPageTest

### 4.1 是什么
开源的网页性能测试工具，最初由AOL开发。

### 4.2 与普通爬虫的区别

普通爬虫(requests/scrapy):
- 只能获取HTML
- 不执行JavaScript
- 看不到动态加载内容

WebPageTest:
- 真实浏览器渲染
- 执行所有JavaScript
- 捕获AJAX/API请求
- 获取完整资源列表

### 4.3 网站
- https://www.webpagetest.org/ (公开测试)
- https://github.com/AquaticInformatics/webpagetest (开源代码)

---

## 五、Google BigQuery

### 5.1 是什么
Google Cloud的数据仓库服务，专门处理PB级数据分析。

### 5.2 特点
- 无服务器(不用管基础设施)
- SQL查询(用标准SQL分析数据)
- 超大规模(可处理PB级数据)
- 按量付费(查询多少付多少)

### 5.3 查询示例
SELECT url, status, resp_content_type
FROM httparchive.requests.2024_01_01_desktop
WHERE url LIKE '%/api/%'
LIMIT 10000

-- 这个查询可能扫描TB级数据，几秒出结果

---

## 六、Commonspeak2

### 6.1 是什么
Assetnote开发的工具，从HTTP Archive的BigQuery数据集中提取真实网络数据生成字典。

### 6.2 工作原理
HTTP Archive(每月爬取全球Top网站) --> BigQuery数据库(PB级) --> Commonspeak2查询 --> 提取真实的子域名/目录/参数/文件名 --> 生成字典

### 6.3 与人工字典对比

| 对比项 | 人工字典(SecLists) | Commonspeak2 |
|--------|---------------------|--------------|
| 数据来源 | 安全研究员手动收集 | 真实网络流量 |
| 更新频率 | 不定期 | 每月自动 |
| 覆盖范围 | 常见+经验 | 真实存在的 |
| 误报率 | 较高(很多不存在) | 较低(真实数据) |
| 大小 | 中等 | 巨大 |

### 6.4 GitHub仓库
https://github.com/assetnote/commonspeak2

---

## 七、Assetnote

### 7.1 是什么
澳大利亚安全公司，专注于攻击面管理(ASM)。

### 7.2 主要产品
1. Assetnote Platform - 企业级攻击面监控(付费)
2. Wordlists - 免费字典
3. Kiterunner - 智能API发现工具(开源)
4. Commonspeak2 - 字典生成工具(开源)

### 7.3 Assetnote Wordlists内容

| 类型 | 说明 | 大小 | 适用场景 |
|------|------|------|----------|
| httparchive_subdomains | 子域名字典 | ~100MB+ | 子域名爆破 |
| httparchive_directories | 目录路径 | ~500MB+ | 目录发现 |
| httparchive_parameters | GET/POST参数名 | ~50MB+ | 参数发现 |
| httparchive_apiroutes | API路由 | ~200MB+ | API发现 |
| httparchive_js_files | JS文件名 | ~100MB+ | JS文件发现 |
| httparchive_php_files | PHP文件名 | ~100MB+ | PHP文件发现 |
| httparchive_aspx_files | ASPX文件名 | ~50MB+ | .NET文件发现 |
| swagger-wordlist | Swagger/OpenAPI路径 | ~50MB | API文档发现 |
| kiterunner(.kite) | 上下文感知路由 | ~200MB+ | 智能API发现 |

---

## 八、费用与赞助

### 8.1 HTTP Archive赞助商

| 赞助商 | 提供什么 |
|--------|----------|
| Google | BigQuery存储和查询费用(主要赞助) |
| Akamai | CDN和带宽 |
| Fastly | CDN支持 |
| Mozilla | 资金支持 |
| Internet Archive | 基础设施 |

### 8.2 费用估算

存储费用(BigQuery):
- 数据量: ~100+ PB
- 存储价格: 0.02美元/GB/月
- 月费用: ~200万美元+(但Google赞助)

爬取费用:
- 800万网站 x 每月一次
- 带宽: 几十TB
- 服务器: 分布式集群
- 月费用: ~10万美元+(Akamai/Fastly赞助)

查询费用:
- 公开数据集，用户自己付
- 5美元/TB查询量
- 但有免费额度(1TB/月)

### 8.3 Google为什么愿意赞助
1. 推广BigQuery - 展示其处理大数据的能力
2. Web生态 - Google靠Web赚钱，需要Web更好
3. SEO/性能 - 数据帮助Google优化搜索排名算法
4. 公益形象 - 开源社区好感度
5. 人才招聘 - 吸引对大数据感兴趣的工程师

---

## 九、安全研究应用场景

### 9.1 适合使用Assetnote Wordlists的场景
- 云服务器批量扫描(VPS上跑subfinder/httpx/ffuf)
- 大规模子域名枚举
- 全球资产发现
- Bug Bounty大范围侦察
- 红队评估(外部攻击面测绘)

### 9.2 不适合的场景
- 本地单目标测试(太慢)
- 有时间限制的渗透测试
- 低带宽环境
- 需要隐蔽的测试

---

## 十、主流安全字典库对比

| 库 | 大小 | 特点 | 适用场景 |
|---|---|---|---|
| SecLists | ~1GB+ | 最全面、分类清晰、社区活跃 | 通用渗透测试 |
| PayloadsAllTheThings | ~200MB | 漏洞利用导向、带技巧说明 | 漏洞研究/CTF |
| fuzzdb | ~100MB | 经典老牌、攻击模式全 | Web Fuzzing |
| Assetnote Wordlists | ~10GB+ | 超大规模、真实数据 | 大规模资产发现 |
| OneListForAll | ~500MB | 合并多个库、去重 | 目录爆破 |
| Bo0oM/fuzz.txt | ~5MB | 精简高效 | 快速目录扫描 |

---

## 十一、小说创作要点

### 11.1 技术细节可用于
- 黑客角色的专业对话
- 大规模网络攻击的技术背景
- 情报收集的真实流程
- 科技公司的数据基础设施描写

### 11.2 戏剧性元素
- Google掌握全球网站访问数据(隐私争议)
- 安全研究员利用公开数据发现漏洞
- 攻击面管理是企业安全的关键
- 真实数据vs人工字典的效率差异

### 11.3 可能的情节
- 主角利用HTTP Archive数据发现目标公司的隐藏API
- 通过Chrome UX Report追踪某个神秘网站的访问量变化
- 利用BigQuery查询发现大规模数据泄露
- Assetnote式的攻击面监控发现供应链攻击

---

> 本文档整理自实际安全研究工作中的技术讨论
> 可作为网络安全题材小说的技术参考素材

Chrome 用户 --> Chrome UX Report --> HTTP Archive --> BigQuery --> Commonspeak2 --> Assetnote Wordlists --> 安全研究员

---

## 二、HTTP Archive (httparchive.org)

### 2.1 定义
非营利项目，从 2010 年开始定期爬取全球 Top 网站，记录网页的完整技术数据。
被称为"互联网的考古学家"。

### 2.2 数据规模
- 网站数量: 800万+
- 数据总量: PB 级 (1 PB = 1000 TB)
- 历史跨度: 2010年至今
- 更新频率: 每月一次

### 2.3 包含的数据类型

| 数据类型 | 具体内容 | 安全研究用途 |
|----------|----------|--------------|
| 请求 URL | 完整的 HTTP 请求地址 | 提取目录/文件/参数名 |
| 响应头 | Server, X-Powered-By 等 | 技术栈识别、指纹分析 |
| HTML 内容 | 页面完整源码 | 提取链接/表单/隐藏字段 |
| JavaScript | 所有加载的 JS 文件内容 | 提取 API 端点、密钥泄露 |
| CSS | 样式表 | CDN 识别 |
| 图片/字体 | 资源 URL | 第三方服务识别 |
| 性能数据 | 加载时间、资源大小 | - |
| 技术检测 | 使用的框架/CMS/库 | 漏洞关联 |
| 第三方资源 | 外部 JS/CSS/API 调用 | 供应链攻击分析 |

### 2.4 小说素材价值
- 这是一个"记录整个互联网历史"的项目
- 可以追溯任何网站 10+ 年的技术演变
- 相当于互联网的"时光机"

