#!/usr/bin/env python3
"""
CryptoTool - Burp Suite 加解密工具
主入口文件
"""
import sys
import os

# 添加项目目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gui.main_window import main

if __name__ == '__main__':
    main()
