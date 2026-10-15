@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo 正在创建虚拟环境 .venv ...
py -3 -m venv .venv 2>nul || python -m venv .venv
if not exist ".venv\Scripts\python.exe" goto err
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto err
echo.
echo 环境就绪：运行 run.bat 启动，或 pytest 跑测试。
pause
exit /b 0
:err
echo.
echo 安装失败：请确认已安装 Python 3.10+ 且网络可用。
pause
exit /b 1
