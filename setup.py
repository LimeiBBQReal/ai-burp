from setuptools import setup, find_packages

setup(
    name="aiburp",
    version="4.0.0",
    description="AI 渗透测试 HTTP 工具 - 像赌神一样精准出牌",
    packages=find_packages(),
    package_data={
        "": ["../payloads/**/*.txt"],
    },
    include_package_data=True,
    install_requires=[
        "httpx>=0.24.0",
        "requests>=2.28.0",
        "dnspython>=2.3.0",
        "python-dotenv>=1.0.0",
    ],
    extras_require={
        "full": [
            "mitmproxy>=10.0.0",
            "playwright>=1.40.0",
            # V4 traffic 层可选协议库
            "websockets>=12.0",          # WebSocket adapter
            "pymysql>=1.1.0",            # MySQL adapter
            "cryptography>=41.0.0",      # TLS 证书解析
            "impacket>=0.11.0",          # SMB adapter (可选, 缺失时降级)
        ],
        # 单独的可选协议库 (按需安装)
        "ws": ["websockets>=12.0"],
        "mysql": ["pymysql>=1.1.0"],
        "tls": ["cryptography>=41.0.0"],
        "smb": ["impacket>=0.11.0"],
    },
    entry_points={
        "console_scripts": [
            "aiburp=aiburp.cli:main",
            "aiburp-ide=aiburp.ide_cli:main",
        ],
    },
    python_requires=">=3.9",  # asyncio.to_thread 需要 3.9+
)
