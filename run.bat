@echo off
chcp 65001 >nul
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    echo [错误] 未找到 .venv，请先运行 setup.bat 创建环境。
    pause
    exit /b 1
)
".venv\Scripts\python.exe" main.py %*
