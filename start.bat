@echo off
chcp 65001 >nul
echo ========================================
echo   CryptoTool - Burp Suite 加解密工具
echo ========================================
echo.

echo [1/3] 检查Python环境...
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 未找到Python，请先安装Python 3.9+
    pause
    exit /b 1
)

echo [2/3] 安装依赖...
pip install -r requirements.txt -q

echo [3/3] 启动程序...
echo.
python main.py

pause
