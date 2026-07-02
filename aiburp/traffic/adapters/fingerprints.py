"""
协议指纹库 - UPM 协议自动识别的基础数据.

两类数据:
    1. KNOWN_PORT_SERVICE: 端口 -> (协议, 服务) 的优先映射
    2. BANNER_SIGNATURES:  banner 文本 -> (服务, 版本提取正则) 的指纹规则

维护原则:
    - 端口映射优先于 banner 探测 (端口是确定的, banner 可能被改)
    - banner 规则按攻击价值排序, Redis/SSH/Docker 等高危服务靠前
    - 不追求穷举, 只收录红队高频目标服务
"""

import re
from typing import Dict, List, Optional, Tuple

# ============================================================
# 1. 已知端口 -> 协议/服务映射
# ============================================================

# port -> (upm_protocol, service_name)
KNOWN_PORT_SERVICE: Dict[int, Tuple[str, str]] = {
    # --- Web ---
    80:    ("http", "http"),
    8080:  ("http", "http-alt"),
    8000:  ("http", "http-alt"),
    8888:  ("http", "http-alt"),
    443:   ("http", "https"),
    8443:  ("http", "https-alt"),
    # --- 远程访问 ---
    22:    ("ssh", "ssh"),
    23:    ("tcp", "telnet"),
    3389:  ("tcp", "rdp"),
    5900:  ("tcp", "vnc"),
    # --- 数据库 ---
    3306:  ("mysql", "mysql"),
    5432:  ("tcp", "postgresql"),
    1433:  ("tcp", "mssql"),
    1521:  ("tcp", "oracle"),
    27017: ("tcp", "mongodb"),
    6379:  ("tcp", "redis"),
    9042:  ("tcp", "cassandra"),
    # --- 基础设施 ---
    53:    ("dns", "dns"),
    25:    ("tcp", "smtp"),
    21:    ("ftp", "ftp"),
    # --- UDP 服务 (M4 新增) ---
    161:   ("snmp", "snmp"),        # SNMP (默认 public community = 高危)
    162:   ("snmp", "snmp-trap"),
    123:   ("udp", "ntp"),
    137:   ("udp", "netbios-name"),
    138:   ("udp", "netbios-dgram"),
    500:   ("udp", "ipsec-ike"),
    1900:  ("udp", "ssdp-upnp"),
    5353:  ("udp", "mdns"),
    # --- TLS (M4 新增, 443 已在 http, 这里补其它 TLS 端口) ---
    465:   ("tls", "smtps"),        # SMTPS
    636:   ("tls", "ldaps"),        # LDAPS
    989:   ("tls", "ftps-data"),
    990:   ("tls", "ftps"),
    993:   ("tls", "imaps"),
    995:   ("tls", "pop3s"),
    # --- DevOps / Cloud (高危未授权 RCE 重灾区) ---
    2375:  ("tcp", "docker"),         # Docker daemon 无 TLS
    2376:  ("tcp", "docker-tls"),
    10250: ("tcp", "kubelet"),        # Kubelet API
    10255: ("tcp", "kubelet-ro"),
    6443:  ("tcp", "k8s-api"),
    9000:  ("tcp", "portainer"),
    8500:  ("tcp", "consul"),
    # --- 消息队列 ---
    1883:  ("tcp", "mqtt"),
    5672:  ("tcp", "amqp"),
    9092:  ("tcp", "kafka"),
    # --- Java 反序列化重灾区 ---
    1099:  ("rmi", "rmi"),
    8009:  ("tcp", "ajp"),
    8161:  ("tcp", "activemq"),
    # --- SMB (M5 新增) ---
    445:   ("smb", "smb"),
    139:   ("smb", "smb-netbios"),
    # --- 缓存 / 内存 ---
    11211: ("tcp", "memcached"),
    # --- 工控 (ICS/SCADA) ---
    502:   ("tcp", "modbus"),
    102:   ("tcp", "s7"),
}


# ============================================================
# 2. Banner 指纹规则
# ============================================================

# 每条: (匹配正则, 服务名, 版本提取组, 攻击价值 high|medium|low)
BANNER_SIGNATURES: List[Tuple[str, str, Optional[str], str]] = [
    # ---------- 高危服务 (按攻击价值排序) ----------
    # Redis: 兼容几种典型响应 — 错误回包 / RESP bulk string / 命令回包 (+PONG/-ERR)
    (r"^-ERR.*\r?\n|^\$[0-9]+\r?\n|^\*1\r?\n\$4\r?\nPING|^\+PONG\r?\n|^redis_version", "redis", None, "high"),
    (r"^SSH-(?P<ver>[\d.]+)-(?P<product>\S+)",              "ssh",     "ver",  "high"),
    (r"^RFB 00(?P<ver>\d{3})\d*",                            "vnc",     "ver",  "high"),
    # Docker daemon 一般先发 GET 才返回 JSON, 但 2375 端口 TCP 握手后会回响
    (r"\{\"[A-Za-z\_]+\".*Docker",                           "docker",  None,   "high"),
    (r"HTTP/[\d.]+\s+\d{3}",                                 "http",    None,   "medium"),
    # ---------- 数据库 ----------
    (r"mariadb|mysql",                                       "mysql",   None,   "high"),
    (r"postgresql|FATAL.*postgres",                          "postgres",None,   "high"),
    (r"microsoft sql server|SQL Server",                     "mssql",   None,   "high"),
    (r"oracle.*TNS",                                         "oracle",  None,   "high"),
    (r"It seems you are trying to access MongoDB",           "mongodb", None,   "high"),
    # ---------- 邮件 ----------
    (r"^220.*postfix",                                       "smtp",    None,   "low"),
    (r"^220.*sendmail",                                      "smtp",    None,   "low"),
    # ---------- 文件 ----------
    (r"^220.*(vsftpd|proftpd|pure-ftpd|FileZilla)",          "ftp",     None,   "low"),
    # ---------- 应用服务器 ----------
    (r"Apache-Coyote|Tomcat",                                "tomcat",  None,   "medium"),
    (r"Jetty",                                               "jetty",   None,   "medium"),
    (r"nginx",                                               "nginx",   None,   "medium"),
    # ---------- 中间件 (Java 反序列化) ----------
    (r"ActiveMQ|JBoss|WebLogic",                             "jboss",   None,   "high"),
    (r"rmiregistry|RMI",                                     "rmi",     None,   "high"),
    # ---------- 工控 ----------
    # 注: Modbus 没有可靠的被动 banner. MBAP header 7 字节结构
    # (txn_id 2B | proto_id 2B=0000 | length 2B | unit_id 1B) 与很多二进制协议
    # 撞型, 被动指纹误报率极高. Modbus 检测应走主动发 Function Code 3/4 query,
    # 不在 banner 指纹库里做.
]

# 预编译 (re.I 让 (?i) inline flag 在中间位置也能工作; 旧 Python 不支持中间 inline)
_COMPILED_SIGNATURES = [
    (re.compile(p, re.I | re.M), svc, ver_group, value)
    for p, svc, ver_group, value in BANNER_SIGNATURES
]


def detect_service_by_port(port: int) -> Optional[Tuple[str, str]]:
    """
    根据端口推断协议.

    Returns:
        (upm_protocol, service_name) 或 None
    """
    return KNOWN_PORT_SERVICE.get(int(port))


def detect_service_by_banner(banner: str) -> Optional[Tuple[str, str, str]]:
    """
    根据 banner 文本匹配服务指纹.

    Args:
        banner: 原始 banner 文本 (最多取前 512 字节)

    Returns:
        (service, version, attack_value) 或 None
    """
    if not banner:
        return None
    sample = banner[:512]
    for pat, svc, ver_group, value in _COMPILED_SIGNATURES:
        m = pat.search(sample)
        if m:
            version = m.group(ver_group) if ver_group and ver_group in m.groupdict() else ""
            return (svc, version, value)
    return None


def split_host_port(target: str, default_port: Optional[int] = None) -> Tuple[str, int]:
    """
    解析 "host:port" / "host" / URL.

    Returns:
        (host, port). port 缺省时用 default_port, 再缺省 0.
    """
    # 处理 http(s):// 前缀
    s = target.strip()
    if "://" in s:
        # URL 形式
        from urllib.parse import urlparse
        u = urlparse(s)
        host = u.hostname or s
        port = u.port or (443 if u.scheme == "https" else 80) or default_port or 0
        return host, int(port)

    if ":" in s and s.rsplit(":", 1)[-1].isdigit():
        host, port_s = s.rsplit(":", 1)
        return host, int(port_s)

    return s, int(default_port or 0)
