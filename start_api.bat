@echo off
chcp 65001 >nul
title CryptoTool API Server
echo ========================================
echo   CryptoTool API Server for Burp Suite
echo ========================================
echo.

cd /d "%~dp0"

echo [1/2] 检查虚拟环境...
if not exist "venv\Scripts\python.exe" (
    echo 错误: 虚拟环境不存在，请先创建虚拟环境
    pause
    exit /b 1
)

echo [2/2] 启动API服务器...
echo.
venv\Scripts\python.exe plugins\burp_extension.py

pause
