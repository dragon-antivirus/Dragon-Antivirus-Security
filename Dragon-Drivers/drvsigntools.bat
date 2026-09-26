@echo off
setlocal

REM ===== 定位脚本所在目录 =====
set "SCRIPT_DIR=%~dp0"
set "SIGNTOOL=%SCRIPT_DIR%signtool.exe"

REM ===== 检查 signtool 是否存在 =====
if not exist "%SIGNTOOL%" (
    echo [错误] 在当前目录找不到 signtool.exe：
    echo        %SIGNTOOL%
    echo 请把 signtool.exe 放到脚本同目录下。
    pause
    exit /b 1
)

REM ===== 用户输入 =====
set /p SIGNDATE=请输入签名日期（格式 YYYY-MM-DD，所填日期必须大于2013年且在证书有效范围内）：
set /p CERTPATH=请输入证书路径（.pfx 文件，不能带引号，请确保路径中没有空格）：
set /p CERTPASS=请输入证书密码：
set /p DRIVERPATH=请输入驱动文件路径（.sys 文件，不能带引号，请确保路径中没有空格）：

REM 拼出完整时间（日期 + T00:00:00），用于时间戳 URL
set "FULLTIME=%SIGNDATE%T00:00:00"

echo.
echo ========== 即将执行 ==========
echo 签名日期：%SIGNDATE% （时间默认 00:00:00）
echo 时间戳 URL：http://timers.524228.xyz/%FULLTIME%
echo 证书路径：%CERTPATH%
echo 驱动路径：%DRIVERPATH%
echo signtool：%SIGNTOOL%
echo ==============================
echo.

REM ===== 调整系统时间到指定日期 =====
date %SIGNDATE%
time 00:00:00

REM ===== 执行签名（时间戳 URL 带自定义日期）=====
"%SIGNTOOL%" sign /f "%CERTPATH%" /p "%CERTPASS%" /fd sha1 /t "http://timers.524228.xyz/%FULLTIME%" "%DRIVERPATH%"

REM ===== 让系统自动同步回正确时间 =====
echo.
echo 正在让系统自动同步回正确时间...
net stop w32time >nul 2>&1
net start w32time >nul 2>&1
w32tm /resync

echo.
echo 完成。
pause
endlocal