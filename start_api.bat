@echo off
chcp 65001 >nul
title CryptoTool API Server
echo ========================================
echo   CryptoTool API Server for Burp Suite
echo ========================================
echo.

cd /d "%~dp0"

echo [1/2] 激活虚拟环境...
call venv\Scripts\activate.bat

echo [2/2] 启动API服务器...
echo.
python plugins\burp_extension.py

pause
