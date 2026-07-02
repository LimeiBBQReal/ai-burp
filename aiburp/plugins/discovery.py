"""
AI-Burp 目录发现模块 v1.0.0

功能:
1. 目录爆破 - 发现隐藏目录和文件
2. 智能字典选择 - 根据服务器类型选择字典
3. 401/403 绕过尝试
4. 敏感文件检测

用法:
    aiburp dirfuzz http://target.com --wordlist quick
    aiburp dirfuzz http://target.com --wordlist asp --threads 10
    aiburp dirfuzz http://target.com --wordlist sensitive --bypass
"""

import os
import time
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..sync_wrapper import SyncBurp as Burp
from ..burp import Response


@dataclass
class DirFuzzResult:
    """目录发现结果"""
    url: str
    path: str
    status: int
    length: int
    redirect: str = ""
    title: str = ""
    interesting: bool = False
    reason: str = ""


@dataclass
class DirFuzzReport:
    """目录发现报告"""
    base_url: str
    wordlist: str
    total_tested: int = 0
    results: List[DirFuzzResult] = field(default_factory=list)
    found_dirs: List[DirFuzzResult] = field(default_factory=list)
    found_files: List[DirFuzzResult] = field(default_factory=list)
    auth_required: List[DirFuzzResult] = field(default_factory=list)
    forbidden: List[DirFuzzResult] = field(default_factory=list)
    sensitive: List[DirFuzzResult] = field(default_factory=list)
    server_type: str = ""
    
    def __str__(self):
        lines = [
            "=" * 60,
            "📂 目录发现报告",
            "=" * 60,
            f"目标: {self.base_url}",
            f"字典: {self.wordlist}",
            f"服务器: {self.server_type}",
            f"测试数: {self.total_tested}",
            "",
        ]
        
        if self.found_dirs:
            lines.append(f"📁 发现目录 ({len(self.found_dirs)}):")
            for r in self.found_dirs[:20]:
                lines.append(f"   [{r.status}] {r.path} ({r.length}b) {r.reason}")
        
        if self.found_files:
            lines.append(f"\n📄 发现文件 ({len(self.found_files)}):")
            for r in self.found_files[:20]:
                lines.append(f"   [{r.status}] {r.path} ({r.length}b) {r.reason}")
        
        if self.sensitive:
            lines.append(f"\n⚠️ 敏感文件 ({len(self.sensitive)}):")
            for r in self.sensitive:
                lines.append(f"   [{r.status}] {r.path} - {r.reason}")
        
        if self.auth_required:
            lines.append(f"\n🔐 需要认证 ({len(self.auth_required)}):")
            for r in self.auth_required[:10]:
                lines.append(f"   [{r.status}] {r.path}")
        
        if self.forbidden:
            lines.append(f"\n🚫 禁止访问 ({len(self.forbidden)}):")
            for r in self.forbidden[:10]:
                lines.append(f"   [{r.status}] {r.path}")
        
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)


class DirFuzzer:
    """
    目录发现器
    
    用法:
        fuzzer = DirFuzzer(burp)
        report = fuzzer.fuzz("http://target.com", wordlist="quick")
        print(report)
    """
    
    # 字典路径
    WORDLISTS = {
        # 基础字典
        'quick': 'discovery/dirs_quick.txt',
        'common': 'discovery/dirs_common.txt',
        'medium': 'external/dirs/seclists_raft-small-directories.txt',
        'large': 'external/dirs/seclists_common.txt',
        'full': 'external/dirs/merged_dirs.txt',
        
        # 技术栈特定
        'asp': 'discovery/dirs_asp.txt',
        'sensitive': 'discovery/dirs_sensitive.txt',
        
        # 外部字典 (SecLists)
        'seclists': 'external/dirs/seclists_common.txt',
        'raft-dirs': 'external/dirs/seclists_raft-small-directories.txt',
        'raft-files': 'external/dirs/seclists_raft-small-files.txt',
        'quickhits': 'external/sensitive/seclists_quickhits.txt',
        'backup': 'external/backup/merged_backup.txt',
        'fuzz': 'external/dirs/bo0om_fuzz.txt',
    }
    
    # 敏感文件模式
    SENSITIVE_PATTERNS = [
        (r'\.git', 'Git 仓库'),
        (r'\.env', '环境配置'),
        (r'\.svn', 'SVN 仓库'),
        (r'web\.config', 'IIS 配置'),
        (r'\.htaccess', 'Apache 配置'),
        (r'\.htpasswd', 'Apache 密码'),
        (r'backup', '备份文件'),
        (r'\.sql', 'SQL 文件'),
        (r'\.bak', '备份文件'),
        (r'\.old', '旧文件'),
        (r'config', '配置文件'),
        (r'database', '数据库'),
        (r'phpinfo', 'PHP 信息'),
        (r'swagger', 'API 文档'),
        (r'actuator', 'Spring Actuator'),
        (r'admin', '管理后台'),
        (r'phpmyadmin', 'phpMyAdmin'),
    ]
    
    # 401/403 绕过技术 (参考 BypassPro 优化) - 精简版
    BYPASS_HEADERS = [
        {'X-Original-URL': '/'},
        {'X-Forwarded-For': '127.0.0.1'},
        {'X-Real-IP': '127.0.0.1'},
    ]
    
    # 路径后缀绕过 (BypassPro 风格) - 精简版
    BYPASS_SUFFIXES = [
        '/',           # 尾斜杠
        '/..;/',       # Spring 分号绕过 (重要!)
        '.json',       # JSON 后缀
        '?',           # 空查询
        '%2e/',        # URL 编码点
    ]
    
    # 路径前缀绕过 (BypassPro 风格) - 精简版
    BYPASS_PREFIXES = [
        '/',           # 双斜杠
        '../',         # 上级目录
        '..;/',        # Spring 分号 (重要!)
    ]
    
    # HTTP 方法变换
    BYPASS_METHODS = ['GET', 'POST', 'HEAD']
    
    # 旧的 BYPASS_PATHS 保留兼容
    BYPASS_PATHS = [
        '/',           # 原始
        '//',          # 双斜杠
        '/./',         # 点斜杠
        '/..;/',       # 分号绕过
        '/%2e/',       # URL 编码
        '/%252e/',     # 双重编码
        '/;/',         # 分号
        '/.;/',        # 点分号
    ]
    
    def __init__(self, burp: Burp, threads: int = 5):
        self.burp = burp
        self.threads = threads
        # 路径: plugins/discovery.py -> plugins -> aiburp -> ai-burp/payloads
        self.payloads_dir = Path(__file__).parent.parent.parent / 'payloads'
    
    def _load_wordlist(self, name: str) -> List[str]:
        """加载字典"""
        if name in self.WORDLISTS:
            path = self.payloads_dir / self.WORDLISTS[name]
        else:
            path = Path(name)
        
        if not path.exists():
            print(f"⚠️ 字典不存在: {path}")
            return []
        
        words = []
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    words.append(line)
        
        return words
    
    def _detect_server(self, url: str) -> str:
        """检测服务器类型"""
        try:
            r = self.burp.get(url)
            server = r.headers.get('server', '').lower()
            powered = r.headers.get('x-powered-by', '').lower()
            
            if 'iis' in server or 'asp' in powered:
                return 'iis'
            elif 'apache' in server:
                return 'apache'
            elif 'nginx' in server:
                return 'nginx'
            elif 'php' in powered:
                return 'php'
            else:
                return 'unknown'
        except:
            return 'unknown'
    
    def _is_sensitive(self, path: str) -> Optional[str]:
        """检查是否是敏感文件"""
        path_lower = path.lower()
        for pattern, desc in self.SENSITIVE_PATTERNS:
            if re.search(pattern, path_lower):
                return desc
        return None
    
    def _extract_title(self, html: str) -> str:
        """提取页面标题"""
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        return match.group(1).strip()[:50] if match else ""
    
    def _test_path(self, base_url: str, path: str, baseline_404_length: int) -> Optional[DirFuzzResult]:
        """测试单个路径"""
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        
        try:
            r = self.burp.get(url)
            
            # 跳过明显的 404
            if r.status == 404:
                return None
            
            # 检查软 404 (响应大小接近 404 页面)
            if r.status == 200 and baseline_404_length > 0:
                if abs(r.length - baseline_404_length) < 50:
                    return None
            
            result = DirFuzzResult(
                url=url,
                path=path,
                status=r.status,
                length=r.length,
                redirect=r.headers.get('location', ''),
                title=self._extract_title(r.body),
            )
            
            # 标记有趣的结果
            if r.status == 200:
                result.interesting = True
                result.reason = "OK"
            elif r.status in [301, 302]:
                result.interesting = True
                result.reason = f"重定向 -> {result.redirect[:30]}"
            elif r.status == 401:
                result.interesting = True
                result.reason = "需要认证"
            elif r.status == 403:
                result.interesting = True
                result.reason = "禁止访问"
            
            # 检查敏感文件
            sensitive = self._is_sensitive(path)
            if sensitive:
                result.reason = f"⚠️ {sensitive}"
            
            return result
            
        except Exception as e:
            return None
    
    def _try_bypass(self, base_url: str, path: str) -> List[DirFuzzResult]:
        """
        尝试绕过 401/403 (BypassPro 风格增强版)
        
        策略:
        1. 路径后缀变体
        2. 路径前缀变体  
        3. Header 绕过
        4. HTTP 方法变换
        """
        results = []
        url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
        
        # 获取原始响应作为基线
        try:
            baseline = self.burp.get(url)
            baseline_status = baseline.status
            baseline_length = baseline.length
        except:
            return results
        
        # 1. 路径后缀变体
        for suffix in self.BYPASS_SUFFIXES:
            if not suffix:
                continue
            test_url = f"{url}{suffix}"
            try:
                r = self.burp.get(test_url)
                if r.status == 200 and r.status != baseline_status:
                    # 检查是否真的不同 (简单相似度)
                    if abs(r.length - baseline_length) > 100:
                        results.append(DirFuzzResult(
                            url=test_url,
                            path=f"{path}{suffix}",
                            status=r.status,
                            length=r.length,
                            interesting=True,
                            reason=f"后缀绕过: {suffix}"
                        ))
            except:
                pass
        
        # 2. 路径前缀变体 (对每个路径节点)
        path_parts = path.strip('/').split('/')
        if len(path_parts) > 0:
            for prefix in self.BYPASS_PREFIXES:
                if not prefix:
                    continue
                # 在第一个节点前添加前缀
                test_path = f"{prefix}{path.lstrip('/')}"
                test_url = f"{base_url.rstrip('/')}/{test_path}"
                try:
                    r = self.burp.get(test_url)
                    if r.status == 200 and r.status != baseline_status:
                        if abs(r.length - baseline_length) > 100:
                            results.append(DirFuzzResult(
                                url=test_url,
                                path=test_path,
                                status=r.status,
                                length=r.length,
                                interesting=True,
                                reason=f"前缀绕过: {prefix}"
                            ))
                except:
                    pass
        
        # 3. Header 绕过
        for headers in self.BYPASS_HEADERS:
            try:
                r = self.burp.request("GET", url, headers=headers)
                if r.status == 200 and r.status != baseline_status:
                    header_name = list(headers.keys())[0]
                    results.append(DirFuzzResult(
                        url=url,
                        path=path,
                        status=r.status,
                        length=r.length,
                        interesting=True,
                        reason=f"Header 绕过: {header_name}"
                    ))
            except:
                pass
        
        # 4. HTTP 方法变换
        for method in self.BYPASS_METHODS:
            if method == 'GET':
                continue
            try:
                r = self.burp.request(method, url)
                if r.status == 200 and r.status != baseline_status:
                    results.append(DirFuzzResult(
                        url=url,
                        path=path,
                        status=r.status,
                        length=r.length,
                        interesting=True,
                        reason=f"方法绕过: {method}"
                    ))
            except:
                pass
        
        return results
    
    def fuzz(
        self, 
        url: str, 
        wordlist: str = "quick",
        extensions: List[str] = None,
        bypass: bool = False,
        recursive: bool = False,
        max_depth: int = 2,
        combo_mode: bool = False
    ) -> DirFuzzReport:
        """
        目录爆破
        
        Args:
            url: 目标 URL
            wordlist: 字典名称 (quick/common/asp/sensitive) 或文件路径
            extensions: 扩展名列表 (如 ['.php', '.asp'])
            bypass: 是否尝试绕过 401/403
            recursive: 是否递归扫描
            max_depth: 最大递归深度
            combo_mode: 组合模式 - 目录+文件组合 FUZZ (用于 401 站点)
        
        Returns:
            DirFuzzReport 对象
        """
        report = DirFuzzReport(base_url=url, wordlist=wordlist)
        
        print("=" * 60)
        print("📂 AI-Burp 目录发现")
        print("=" * 60)
        print(f"目标: {url}")
        print(f"字典: {wordlist}")
        if combo_mode:
            print("模式: 组合模式 (目录+文件)")
        
        # 检测服务器类型
        report.server_type = self._detect_server(url)
        print(f"服务器: {report.server_type}")
        
        # 加载字典
        words = self._load_wordlist(wordlist)
        if not words:
            print("❌ 字典为空")
            return report
        
        # 组合模式: 生成 目录/文件 组合
        if combo_mode:
            words = self._generate_combo_paths(words, report.server_type)
            print(f"组合后字典大小: {len(words)}")
        # 添加扩展名
        elif extensions:
            extended = []
            for word in words:
                extended.append(word)
                for ext in extensions:
                    extended.append(f"{word}{ext}")
            words = extended
        
        print(f"字典大小: {len(words)}")
        print("")
        
        # 获取 404 基线
        baseline_404 = self.burp.get(f"{url}/nonexistent_path_12345")
        baseline_404_length = baseline_404.length if baseline_404.status == 404 else 0
        
        # 获取 401 基线 (用于组合模式)
        baseline_401_length = 0
        if combo_mode:
            baseline_401 = self.burp.get(url)
            if baseline_401.status == 401:
                baseline_401_length = baseline_401.length
        
        # 多线程扫描
        print("🔍 扫描中...")
        tested = 0
        found = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._test_path, url, word, baseline_404_length): word 
                for word in words
            }
            
            for future in as_completed(futures):
                tested += 1
                result = future.result()
                
                if result:
                    # 组合模式下，跳过与 401 基线相同大小的响应
                    if combo_mode and result.status == 401:
                        if baseline_401_length > 0 and abs(result.length - baseline_401_length) < 50:
                            continue
                    
                    report.results.append(result)
                    
                    # 分类
                    if result.status == 200:
                        if '.' in result.path:
                            report.found_files.append(result)
                        else:
                            report.found_dirs.append(result)
                        found += 1
                        print(f"   ✅ [{result.status}] /{result.path} ({result.length}b)")
                    elif result.status == 401:
                        report.auth_required.append(result)
                        if not combo_mode:  # 组合模式下不打印每个 401
                            print(f"   🔐 [{result.status}] /{result.path}")
                    elif result.status == 403:
                        report.forbidden.append(result)
                        print(f"   🚫 [{result.status}] /{result.path}")
                    elif result.status in [301, 302]:
                        report.found_dirs.append(result)
                        found += 1
                        print(f"   ➡️ [{result.status}] /{result.path} -> {result.redirect[:30]}")
                    
                    # 敏感文件
                    sensitive = self._is_sensitive(result.path)
                    if sensitive and result.status in [200, 301, 302]:
                        result.reason = sensitive
                        report.sensitive.append(result)
                
                # 进度
                if tested % 100 == 0:
                    print(f"   ... 已测试 {tested}/{len(words)}, 发现 {found}")
                
                time.sleep(self.burp.delay * 0.3)
        
        report.total_tested = tested
        
        # 尝试绕过
        if bypass and (report.auth_required or report.forbidden):
            print("\n🔓 尝试绕过 401/403...")
            for r in report.auth_required[:5] + report.forbidden[:5]:
                bypassed = self._try_bypass(url, r.path)
                if bypassed:
                    for b in bypassed:
                        print(f"   ✅ 绕过成功: {b.path} ({b.reason})")
                        report.found_dirs.append(b)
        
        print(f"\n✅ 完成! 发现 {len(report.found_dirs)} 目录, {len(report.found_files)} 文件")
        
        return report
    
    def _generate_combo_paths(self, words: List[str], server_type: str) -> List[str]:
        """生成目录+文件组合路径 (精简版)"""
        # 高价值目录
        dirs = [
            '', 'admin', 'login', 'api', 'config', 'data', 
            'upload', 'files', 'backup', 'test', 'db',
        ]
        
        # 根据服务器类型选择文件
        if server_type == 'iis':
            files = [
                'default.asp', 'default.aspx', 'index.asp', 'index.aspx',
                'login.asp', 'login.aspx', 'admin.asp', 'admin.aspx',
                'web.config', 'test.asp', 'info.asp',
                'config.asp', 'database.asp', 'db.asp',
                'upload.asp', 'user.asp', 'users.asp',
                'product.asp', 'products.asp', 'order.asp',
                'robots.txt', 'sitemap.xml',
            ]
        else:
            files = [
                'index.php', 'index.html', 'login.php', 'admin.php',
                'config.php', 'test.php', 'info.php', 'phpinfo.php',
                '.htaccess', 'robots.txt', 'wp-config.php',
            ]
        
        # 生成组合
        combo = set()
        
        # 单独的文件
        for f in files:
            combo.add(f)
        
        # 目录 + 文件 (只用高价值目录)
        for d in dirs:
            if d:
                for f in files[:10]:  # 只用前10个文件
                    combo.add(f"{d}/{f}")
        
        # 原始字典中的词 + 扩展名
        exts = ['.asp', '.aspx'] if server_type == 'iis' else ['.php', '.html']
        for word in words:
            combo.add(word)
            if '.' not in word:
                for ext in exts:
                    combo.add(f"{word}{ext}")
        
        return list(combo)


def dirfuzz_command(burp: Burp, url: str, wordlist: str = "quick", 
                    extensions: str = None, bypass: bool = False,
                    threads: int = 5, combo: bool = False) -> str:
    """目录发现命令入口"""
    fuzzer = DirFuzzer(burp, threads=threads)
    
    ext_list = None
    if extensions:
        ext_list = [e.strip() for e in extensions.split(",")]
    
    report = fuzzer.fuzz(url, wordlist=wordlist, extensions=ext_list, 
                         bypass=bypass, combo_mode=combo)
    return str(report)


def bypass403_command(burp: Burp, url: str, aggressive: bool = False) -> str:
    """
    403 绕过命令入口 (BypassPro 风格)
    
    用法:
        aiburp bypass403 http://target.com/admin
        aiburp bypass403 http://target.com/admin --aggressive
    
    Args:
        url: 返回 403 的 URL
        aggressive: 是否使用激进模式 (更多变体，可能触发 WAF)
    """
    fuzzer = DirFuzzer(burp)
    
    print("=" * 60)
    print("🔓 AI-Burp 403 绕过")
    print("=" * 60)
    print(f"目标: {url}")
    print(f"模式: {'激进' if aggressive else '标准'}")
    print("")
    
    # 获取原始响应
    try:
        baseline = burp.get(url)
        print(f"原始状态: {baseline.status}")
        print(f"原始大小: {baseline.length}b")
    except Exception as e:
        return f"❌ 无法访问目标: {e}"
    
    if baseline.status not in [401, 403, 404]:
        print(f"⚠️ 目标返回 {baseline.status}，不是 401/403/404")
    
    print("")
    print("🔍 测试绕过技术...")
    
    # 解析 URL
    from urllib.parse import urlparse
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path
    
    results = fuzzer._try_bypass(base_url, path)
    
    # 输出结果
    if results:
        print("")
        print("=" * 60)
        print(f"✅ 发现 {len(results)} 个绕过方法!")
        print("=" * 60)
        for r in results:
            print(f"   [{r.status}] {r.url}")
            print(f"         大小: {r.length}b | 方法: {r.reason}")
            print("")
        return f"发现 {len(results)} 个绕过方法"
    else:
        print("")
        print("❌ 未发现绕过方法")
        return "未发现绕过方法"
