"""
AI-Burp 指纹识别模块

基于 Wappalyzer 指纹库实现技术栈识别

使用方式:
    from aiburp.fingerprint import TechDetector
    
    detector = TechDetector()
    result = detector.detect("https://target.com")
    
    print(result.technologies)  # ['WordPress', 'PHP', 'MySQL', 'Apache']
    print(result.categories)    # ['CMS', 'Programming languages', 'Databases']
"""

from .detector import TechDetector, TechResult
from .wappalyzer import WappalyzerDB

__all__ = ['TechDetector', 'TechResult', 'WappalyzerDB']
