@echo off
chcp 65001 >nul
title CryptoTool - Burp Suite 加解密工具
echo ========================================
echo   CryptoTool - Burp Suite 加解密工具
echo ========================================
echo.

cd /d "%~dp0"

echo [1/2] 检查虚拟环境...
if not exist "venv\Scripts\python.exe" (
    echo 错误: 虚拟环境不存在，请先创建虚拟环境
    pause
    exit /b 1
)

echo [2/2] 启动GUI程序...
echo.
venv\Scripts\python.exe main.py

pause
