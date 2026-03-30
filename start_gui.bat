@echo off
chcp 65001 >nul
title CryptoTool - Burp Suite 加解密工具
echo ========================================
echo   CryptoTool - Burp Suite 加解密工具
echo ========================================
echo.

cd /d "%~dp0"

echo [1/2] 激活虚拟环境...
call venv\Scripts\activate.bat

echo [2/2] 启动GUI程序...
echo.
python main.py

pause
