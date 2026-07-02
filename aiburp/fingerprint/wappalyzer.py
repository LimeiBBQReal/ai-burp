"""
Wappalyzer 指纹库加载器

从 Wappalyzer 官方 JSON 加载指纹数据
"""

import os
import json
import re
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class Technology:
    """技术指纹"""
    name: str
    categories: List[int] = field(default_factory=list)
    website: str = ""
    icon: str = ""
    
    # 匹配规则
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    html: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)
    scripts: List[str] = field(default_factory=list)
    js: Dict[str, str] = field(default_factory=dict)
    url: List[str] = field(default_factory=list)
    implies: List[str] = field(default_factory=list)
    excludes: List[str] = field(default_factory=list)
    
    # 版本提取
    version: str = ""


# 内置精简指纹库 (常见技术栈)
BUILTIN_FINGERPRINTS = {
    # Web 服务器
    "Apache": {
        "cats": [22],
        "headers": {"Server": r"Apache(?:/([\\d.]+))?"},
        "implies": []
    },
    "Nginx": {
        "cats": [22],
        "headers": {"Server": r"nginx(?:/([\\d.]+))?"},
        "implies": []
    },
    "IIS": {
        "cats": [22],
        "headers": {"Server": r"Microsoft-IIS(?:/([\\d.]+))?"},
        "implies": ["Windows Server"]
    },
    "LiteSpeed": {
        "cats": [22],
        "headers": {"Server": r"LiteSpeed"}
    },
    
    # 编程语言
    "PHP": {
        "cats": [27],
        "headers": {"X-Powered-By": r"PHP(?:/([\\d.]+))?", "Server": r"PHP(?:/([\\d.]+))?"},
        "cookies": {"PHPSESSID": ""},
        "url": [r"\\.php(?:$|\\?)"]
    },
    "ASP.NET": {
        "cats": [27],
        "headers": {"X-Powered-By": r"ASP\\.NET", "X-AspNet-Version": r"([\\d.]+)"},
        "cookies": {"ASP.NET_SessionId": "", "ASPSESSIONID": ""},
        "url": [r"\\.aspx?(?:$|\\?)"]
    },
    "Java": {
        "cats": [27],
        "headers": {"X-Powered-By": r"Servlet|JSP|JSF"},
        "cookies": {"JSESSIONID": ""},
        "url": [r"\\.jsp(?:$|\\?)", r"\\.do(?:$|\\?)"]
    },
    "Python": {
        "cats": [27],
        "headers": {"Server": r"Python|Werkzeug|gunicorn|uvicorn"}
    },
    "Ruby": {
        "cats": [27],
        "headers": {"X-Powered-By": r"Phusion Passenger", "Server": r"Passenger|Puma|Unicorn"}
    },
    "Node.js": {
        "cats": [27],
        "headers": {"X-Powered-By": r"Express"}
    },
    
    # CMS
    "WordPress": {
        "cats": [1, 11],
        "headers": {"X-Powered-By": r"WordPress", "Link": r"<[^>]+>; rel=\"https://api\\.w\\.org/\""},
        "meta": {"generator": r"WordPress(?: ([\\d.]+))?"},
        "html": [r"/wp-content/", r"/wp-includes/", r"wp-emoji-release\\.min\\.js"],
        "implies": ["PHP", "MySQL"]
    },
    "Drupal": {
        "cats": [1],
        "headers": {"X-Drupal-Cache": "", "X-Generator": r"Drupal(?: ([\\d.]+))?"},
        "meta": {"generator": r"Drupal(?: ([\\d.]+))?"},
        "html": [r"Drupal\\.settings", r"/sites/default/files/", r"drupal\\.js"],
        "implies": ["PHP"]
    },
    "Joomla": {
        "cats": [1],
        "meta": {"generator": r"Joomla!(?: ([\\d.]+))?"},
        "html": [r"/media/jui/", r"/media/system/js/", r"Joomla!"],
        "implies": ["PHP"]
    },
    "Magento": {
        "cats": [6],
        "cookies": {"frontend": ""},
        "html": [r"Mage\\.Cookies", r"/skin/frontend/", r"var BLANK_URL = '[^']+/js/blank\\.html'"],
        "implies": ["PHP", "MySQL"]
    },
    "Shopify": {
        "cats": [6],
        "headers": {"X-ShopId": "", "X-Shopify-Stage": ""},
        "html": [r"cdn\\.shopify\\.com", r"Shopify\\.theme"],
        "scripts": [r"cdn\\.shopify\\.com"]
    },
    "PrestaShop": {
        "cats": [6],
        "meta": {"generator": r"PrestaShop"},
        "html": [r"prestashop", r"/modules/blockcart/"],
        "implies": ["PHP", "MySQL"]
    },
    "OpenCart": {
        "cats": [6],
        "html": [r"catalog/view/theme", r"route=common/home", r"index\\.php\\?route="],
        "implies": ["PHP"]
    },
    "WooCommerce": {
        "cats": [6],
        "meta": {"generator": r"WooCommerce(?: ([\\d.]+))?"},
        "html": [r"woocommerce", r"/wp-content/plugins/woocommerce/"],
        "implies": ["WordPress"]
    },
    
    # 框架
    "Laravel": {
        "cats": [18],
        "cookies": {"laravel_session": ""},
        "implies": ["PHP"]
    },
    "Django": {
        "cats": [18],
        "cookies": {"csrftoken": "", "sessionid": ""},
        "html": [r"__admin_media_prefix__", r"csrfmiddlewaretoken", r"django\\.contrib"],
        "implies": ["Python"]
    },
    "Flask": {
        "cats": [18],
        "headers": {"Server": r"Werkzeug"},
        "implies": ["Python"]
    },
    "Spring": {
        "cats": [18],
        "headers": {"X-Application-Context": ""},
        "cookies": {"JSESSIONID": ""},
        "implies": ["Java"]
    },
    "Ruby on Rails": {
        "cats": [18],
        "headers": {"X-Powered-By": r"Phusion Passenger"},
        "meta": {"csrf-param": r"authenticity_token"},
        "implies": ["Ruby"]
    },
    "Express": {
        "cats": [18],
        "headers": {"X-Powered-By": r"Express"},
        "implies": ["Node.js"]
    },
    "Next.js": {
        "cats": [18],
        "headers": {"X-Powered-By": r"Next\\.js"},
        "html": [r"/_next/static/", r"__NEXT_DATA__"],
        "implies": ["Node.js", "React"]
    },
    "Nuxt.js": {
        "cats": [18],
        "html": [r"__NUXT__", r"/_nuxt/"],
        "implies": ["Node.js", "Vue.js"]
    },
    
    # JavaScript 框架
    "jQuery": {
        "cats": [12],
        "scripts": [r"jquery[.-]([\\d.]+)(?:\\.min)?\\.js"],
        "js": {"jQuery.fn.jquery": ""}
    },
    "React": {
        "cats": [12],
        "html": [r"react\\.production\\.min\\.js", r"data-reactroot", r"_reactRootContainer"],
        "scripts": [r"react(?:-dom)?[.-]([\\d.]+)(?:\\.min)?\\.js"]
    },
    "Vue.js": {
        "cats": [12],
        "html": [r"Vue\\.js", r"data-v-[a-f0-9]", r"__vue__"],
        "scripts": [r"vue[.-]([\\d.]+)(?:\\.min)?\\.js"]
    },
    "Angular": {
        "cats": [12],
        "html": [r"ng-app", r"ng-controller", r"ng-version=\"([\\d.]+)\""],
        "scripts": [r"angular[.-]([\\d.]+)(?:\\.min)?\\.js"]
    },
    "Bootstrap": {
        "cats": [66],
        "html": [r"bootstrap\\.min\\.css", r"class=\"[^\"]*\\bcontainer\\b"],
        "scripts": [r"bootstrap[.-]([\\d.]+)(?:\\.min)?\\.js"]
    },
    
    # 数据库
    "MySQL": {
        "cats": [34]
    },
    "PostgreSQL": {
        "cats": [34]
    },
    "MongoDB": {
        "cats": [34]
    },
    "Microsoft SQL Server": {
        "cats": [34]
    },
    "Redis": {
        "cats": [34]
    },
    
    # CDN/云服务
    "Cloudflare": {
        "cats": [31],
        "headers": {"Server": r"cloudflare", "CF-RAY": ""},
        "cookies": {"__cfduid": "", "__cf_bm": ""}
    },
    "Amazon Web Services": {
        "cats": [62],
        "headers": {"X-Amz-Cf-Id": "", "X-Amz-Request-Id": "", "Server": r"AmazonS3"}
    },
    "Google Cloud": {
        "cats": [62],
        "headers": {"X-Cloud-Trace-Context": "", "Server": r"Google Frontend"}
    },
    "Akamai": {
        "cats": [31],
        "headers": {"X-Akamai-Transformed": "", "Server": r"AkamaiGHost"}
    },
    "Fastly": {
        "cats": [31],
        "headers": {"X-Served-By": r"cache-", "X-Fastly-Request-ID": ""}
    },
    
    # 安全/WAF
    "ModSecurity": {
        "cats": [16],
        "headers": {"Server": r"Mod_Security|NOYB"}
    },
    "Sucuri": {
        "cats": [16],
        "headers": {"X-Sucuri-ID": "", "Server": r"Sucuri"}
    },
    "Imperva": {
        "cats": [16],
        "headers": {"X-Iinfo": ""}
    },
    
    # 分析/营销
    "Google Analytics": {
        "cats": [10],
        "html": [r"google-analytics\\.com/(?:ga|analytics)\\.js", r"GoogleAnalyticsObject", r"gtag\\("],
        "scripts": [r"google-analytics\\.com", r"googletagmanager\\.com"]
    },
    "Google Tag Manager": {
        "cats": [42],
        "html": [r"googletagmanager\\.com/gtm\\.js"],
        "scripts": [r"googletagmanager\\.com"]
    },
    "Facebook Pixel": {
        "cats": [10],
        "html": [r"connect\\.facebook\\.net/[^/]+/fbevents\\.js", r"fbq\\("],
        "scripts": [r"connect\\.facebook\\.net"]
    },
    
    # 其他
    "Moodle": {
        "cats": [21],
        "meta": {"keywords": r"moodle"},
        "html": [r"M\\.cfg", r"/theme/yui_combo\\.php", r"moodleData"],
        "implies": ["PHP"]
    },
    "WHMCS": {
        "cats": [6],
        "html": [r"WHMCS", r"whmcs"],
        "cookies": {"WHMCS": ""},
        "implies": ["PHP"]
    },
    "phpMyAdmin": {
        "cats": [3],
        "html": [r"phpMyAdmin", r"pma_"],
        "cookies": {"phpMyAdmin": "", "pma_": ""},
        "implies": ["PHP", "MySQL"]
    },
    "cPanel": {
        "cats": [9],
        "headers": {"Server": r"cpsrvd"},
        "html": [r"cPanel"]
    },
    "Plesk": {
        "cats": [9],
        "headers": {"X-Powered-By": r"PleskLin|PleskWin"},
        "html": [r"Plesk"]
    }
}

# 分类定义
CATEGORIES = {
    1: "CMS",
    3: "Database managers",
    6: "Ecommerce",
    9: "Hosting panels",
    10: "Analytics",
    11: "Blogs",
    12: "JavaScript frameworks",
    16: "Security",
    18: "Web frameworks",
    21: "LMS",
    22: "Web servers",
    27: "Programming languages",
    31: "CDN",
    34: "Databases",
    42: "Tag managers",
    62: "PaaS",
    66: "UI frameworks"
}


class WappalyzerDB:
    """Wappalyzer 指纹库"""
    
    def __init__(self, db_path: str = None):
        self.technologies: Dict[str, Technology] = {}
        self.categories = CATEGORIES.copy()
        
        if db_path and os.path.exists(db_path):
            self._load_from_file(db_path)
        else:
            self._load_builtin()
    
    def _load_builtin(self):
        """加载内置指纹库"""
        for name, data in BUILTIN_FINGERPRINTS.items():
            self.technologies[name] = self._parse_tech(name, data)
    
    def _load_from_file(self, path: str):
        """从文件加载指纹库"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if "technologies" in data:
                for name, tech_data in data["technologies"].items():
                    self.technologies[name] = self._parse_tech(name, tech_data)
            
            if "categories" in data:
                for cat_id, cat_data in data["categories"].items():
                    self.categories[int(cat_id)] = cat_data.get("name", f"Category {cat_id}")
        except Exception as e:
            print(f"加载指纹库失败: {e}, 使用内置库")
            self._load_builtin()
    
    def _parse_tech(self, name: str, data: dict) -> Technology:
        """解析技术指纹"""
        tech = Technology(name=name)
        
        tech.categories = data.get("cats", data.get("categories", []))
        tech.website = data.get("website", "")
        tech.icon = data.get("icon", "")
        
        # 解析匹配规则
        tech.headers = self._normalize_patterns(data.get("headers", {}))
        tech.cookies = self._normalize_patterns(data.get("cookies", {}))
        tech.html = self._normalize_list(data.get("html", []))
        tech.meta = self._normalize_patterns(data.get("meta", {}))
        tech.scripts = self._normalize_list(data.get("scripts", []))
        tech.url = self._normalize_list(data.get("url", []))
        
        # implies
        implies = data.get("implies", [])
        if isinstance(implies, str):
            implies = [implies]
        tech.implies = implies
        
        return tech
    
    def _normalize_patterns(self, patterns) -> Dict[str, str]:
        """标准化模式字典"""
        if not patterns:
            return {}
        if isinstance(patterns, str):
            return {"": patterns}
        return {k: (v if isinstance(v, str) else "") for k, v in patterns.items()}
    
    def _normalize_list(self, items) -> List[str]:
        """标准化列表"""
        if not items:
            return []
        if isinstance(items, str):
            return [items]
        return [str(i) for i in items]
    
    def get_category_name(self, cat_id: int) -> str:
        """获取分类名称"""
        return self.categories.get(cat_id, f"Unknown ({cat_id})")
    
    def get_tech(self, name: str) -> Optional[Technology]:
        """获取技术指纹"""
        return self.technologies.get(name)
    
    def list_technologies(self) -> List[str]:
        """列出所有技术"""
        return list(self.technologies.keys())
    
    def stats(self) -> Dict:
        """统计信息"""
        return {
            "total_technologies": len(self.technologies),
            "total_categories": len(self.categories)
        }
