# AI-Burp 通用资产侦察管线设计

## 核心问题

当前管线针对 CartManager.net 做了大量硬编码假设：
- 假设目标有电商矩阵（17 个站点）
- 假设 PTR 反查能发现大量关联域名
- 假设 CIDR 扫描有效
- 假设需要链式扩散

这些假设对 `example.com` 或 `1.2.3.4` 完全无效。

## 通用性设计原则

### 1. 输入抽象化

```
输入: TARGET (可以是域名、IP、CIDR)
输出: 标准化资产清单 (AssetInventory)
```

### 2. 目标分类器 (Target Classifier)

在管线启动时，先对目标做快速分类：

```python
def classify_target(target):
    """
    返回目标类型:
    - "domain"     — 普通域名
    - "cdn"        — CDN 域名 (Cloudflare/CloudFront/Akamai)
    - "ip"         — 单 IP
    - "cidr"       — IP 段
    - "matrix"     — 域名矩阵 (多个域名共享 IP)
    """
    if is_ip(target):
        return "ip"
    if is_cidr(target):
        return "cidr"
    if is_cdn(target):
        return "cdn"
    if has_multiple_domains(target):
        return "matrix"
    return "domain"
```

### 3. 策略矩阵 (Strategy Matrix)

根据目标类型选择模块组合：

| 目标类型 | 必选模块 | 可选模块 | 跳过模块 |
|----------|----------|----------|----------|
| **domain** | passive_sources, dns_authoritative | cidr_scan, ptr_expand | domain_chain |
| **cdn** | cdn_bypass, passive_sources | ip_recon | cidr_scan |
| **ip** | ip_recon, banner_grab | zone_transfer | passive_sources |
| **cidr** | cidr_scan, port_scan | ptr_expand | passive_sources |
| **matrix** | ptr_expand, domain_chain | cidr_scan, zone_transfer | (全开) |

### 4. 自适应执行引擎

```python
class ReconPipeline:
    def __init__(self, target):
        self.target = target
        self.asset_inventory = AssetInventory()
        self.classifier = TargetClassifier()
        self.strategy = StrategyMatrix()

    def run(self):
        # Step 1: 分类
        target_type = self.classifier.classify(self.target)

        # Step 2: 选择策略
        modules = self.strategy.select_modules(target_type)

        # Step 3: 执行
        for module in modules:
            result = module.execute(self.target, self.asset_inventory)
            self.asset_inventory.merge(result)

        # Step 4: 反馈循环
        self.feedback_loop()

        return self.asset_inventory
```

### 5. 标准化输出格式

```json
{
  "target": "example.com",
  "target_type": "domain",
  "elapsed_s": 120.5,
  "assets": {
    "domains": ["example.com", "www.example.com"],
    "subdomains": ["api.example.com", "admin.example.com"],
    "ips": ["1.2.3.4", "5.6.7.8"],
    "ports": ["1.2.3.4:80", "1.2.3.4:443"],
    "urls": ["https://example.com/", "https://api.example.com/v1"],
    "banners": {"1.2.3.4:80": "nginx/1.18.0"},
    "certs": {"1.2.3.4": {"CN": "example.com", "SAN": ["*.example.com"]}},
    "mx": ["mail.example.com"],
    "ns": ["ns1.example.com", "ns2.example.com"]
  },
  "metadata": {
    "modules_executed": ["passive_sources", "dns_authoritative"],
    "sources_used": ["crt.sh", "OTX", "Wayback"],
    "wildcard_detected": false
  }
}
```

## 模块通用化改造

### 模块 1: passive_sources.py

**当前问题**: 只针对单个域名
**改造**: 支持批量域名输入

```python
def main():
    target = get_target()
    # 从 ptr_expand 读取额外域名
    extra_domains = load_extra_domains()
    all_domains = [target] + extra_domains

    for domain in all_domains:
        results = query_all_sources(domain)
        asset_inventory.add_subdomains(domain, results)
```

### 模块 2: cidr_scan.py

**当前问题**: 只扫 80/443
**改造**: 可配置端口列表

```python
COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995,
                3306, 3389, 5432, 5900, 8080, 8443, 8888, 9090]

def scan_cidr(ip, ports=COMMON_PORTS):
    for port in ports:
        if is_open(ip, port):
            yield {"ip": ip, "port": port, "service": detect_service(ip, port)}
```

### 模块 3: ptr_expand.py

**当前问题**: 假设所有 IP 都有 PTR
**改造**: 优雅处理无 PTR 的情况

```python
def ptr_expand(ips):
    results = {}
    for ip in ips:
        ptr = resolve_ptr(ip)
        if ptr:
            results[ip] = ptr
        else:
            # 尝试 SSL SNI 提取
            cert = extract_cert(ip)
            if cert:
                results[ip] = cert.get("CN")
    return results
```

### 模块 4: domain_chain.py (新增)

**通用链式扩散**

```python
def domain_chain(domains, max_depth=2):
    """
    对每个域名执行:
    1. crt.sh 查询
    2. 子域名爆破 (如果域名有泛解析则跳过)
    3. 递归到下一层
    """
    visited = set()
    queue = list(domains)

    for depth in range(max_depth):
        next_queue = []
        for domain in queue:
            if domain in visited:
                continue
            visited.add(domain)

            # crt.sh
            crt_subs = crt_sh(domain)

            # 检测泛解析
            if has_wildcard(domain):
                continue

            # 子域名爆破
            brute_subs = dns_brute(domain)

            # 合并
            new_subs = crt_subs | brute_subs
            next_queue.extend(new_subs)

        queue = next_queue
        if not queue:
            break

    return visited
```

### 模块 5: zone_transfer.py (新增)

**通用 DNS AXFR**

```python
def zone_transfer(domain):
    """尝试从所有 NS 服务器拉取区域记录"""
    ns_records = get_ns_records(domain)
    for ns in ns_records:
        try:
            axfr = dns.query.xfr(ns, domain, timeout=5)
            for record in axfr:
                yield record
        except Exception:
            continue
```

### 模块 6: ip_recon.py (新增)

**通用 IP 反查**

```python
def ip_recon(ips):
    """对每个 IP 执行:
    1. Shodan API 查询
    2. Censys API 查询
    3. crt.sh IP 证书查询
    4. SSL SNI 提取
    """
    for ip in ips:
        result = {"ip": ip}

        # Shodan
        shodan_data = shodan_host(ip)
        result["shodan"] = shodan_data

        # Censys
        censys_data = censys_host(ip)
        result["censys"] = censys_data

        # crt.sh
        cert_names = crt_sh_ip(ip)
        result["cert_names"] = cert_names

        # SSL SNI
        try:
            cert = ssl.get_server_certificate((ip, 443))
            result["ssl_cert"] = parse_cert(cert)
        except:
            pass

        yield result
```

### 模块 7: search_dork.py (新增)

**通用搜索引擎 Dork**

```python
def search_dork(domains):
    """对每个域名执行 Google/Bing Dork"""
    dorks = [
        'site:{domain}',
        'site:{domain} filetype:pdf',
        'site:{domain} intitle:"admin"',
        'site:{domain} inurl:"login"',
        'site:{domain} inurl:"config"',
        'site:{domain} inurl:"backup"',
        'site:{domain} inurl:".env"',
    ]

    for domain in domains:
        for dork in dorks:
            query = dork.format(domain=domain)
            results = google_search(query)
            yield {"domain": domain, "dork": dork, "results": results}
```

### 模块 8: feedback_loop.py (新增)

**通用反馈循环**

```python
def feedback_loop(asset_inventory, max_rounds=3):
    """
    从 Phase 3 的 URL 中提取新域名
    投喂回 Phase 1
    直到收敛
    """
    for round in range(max_rounds):
        new_domains = extract_domains_from_urls(asset_inventory.urls)

        if len(new_domains) <= 5:
            break

        # 投喂回 passive_sources
        new_assets = passive_sources(new_domains)
        asset_inventory.merge(new_assets)

    return asset_inventory
```

## 管线执行流程

```
┌─────────────────────────────────────────────────────────────────┐
│  Step 0: Target Classifier                                      │
│  ─────────────────────────                                      │
│  输入: TARGET                                                   │
│  输出: target_type (domain/cdn/ip/cidr/matrix)                  │
│  耗时: < 1s                                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 1: Strategy Selection                                     │
│  ─────────────────────────                                      │
│  根据 target_type 选择模块组合                                   │
│  输出: modules_to_execute[]                                     │
│  耗时: < 1s                                                     │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 2: Parallel Execution                                     │
│  ─────────────────────────                                      │
│  并行执行选中的模块                                              │
│  每个模块输出标准化结果                                          │
│  耗时: 5-15 分钟                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 3: Asset Inventory Merge                                  │
│  ─────────────────────────                                      │
│  合并所有模块结果                                                │
│  去重、排序、标准化                                              │
│  耗时: < 10s                                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 4: Feedback Loop (可选)                                   │
│  ─────────────────────────                                      │
│  从 URL 中提取新域名                                             │
│  投喂回 Phase 1                                                  │
│  重复直到收敛                                                    │
│  耗时: 3-10 分钟                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  Step 5: Final Report                                           │
│  ─────────────────────────                                      │
│  生成标准化资产报告                                              │
│  输出: out/final_asset_report.json                               │
│  耗时: < 5s                                                     │
└─────────────────────────────────────────────────────────────────┘
```

## 通用 Workflow 设计

```yaml
# recon.yml — 通用资产侦察 Workflow
name: Recon

on:
  workflow_dispatch:
    inputs:
      target:
        description: '目标 (域名/IP/CIDR)'
        required: true
      target_type:
        description: '目标类型 (auto/domain/cdn/ip/cidr/matrix)'
        default: 'auto'
      max_rounds:
        description: '反馈循环最大轮数'
        default: '3'

jobs:
  classify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install requests dnspython cryptography
      - name: Classify target
        id: classify
        env:
          TARGET: ${{ inputs.target }}
        run: |
          python -c "
          from classifier import classify_target
          target_type = classify_target('${{ inputs.target }}')
          print(f'target_type={target_type}')
          "
        outputs:
          target_type: ${{ steps.classify.outputs.target_type }}

  # 根据 target_type 动态选择模块
  execute:
    needs: classify
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install requests dnspython cryptography
      - name: Execute pipeline
        env:
          TARGET: ${{ inputs.target }}
          TARGET_TYPE: ${{ needs.classify.outputs.target_type }}
          MAX_ROUNDS: ${{ inputs.max_rounds }}
        run: python pipeline.py
```

## 关键优势

1. **输入通用**: 支持域名、IP、CIDR
2. **策略自适应**: 根据目标类型选择模块
3. **输出标准化**: 统一 AssetInventory 格式
4. **可扩展**: 新增模块只需实现标准接口
5. **可组合**: 模块之间通过 AssetInventory 传递数据
