@echo off
setlocal

set EXE_PATH="d:/MiHoYo/Genshin/client/GenshinImpact_3.8.0/GenshinImpact.exe"
set RETRIES=9

:RETRY
%EXE_PATH% -magic %RETRIES%
set EXIT_CODE=%errorlevel%
if %EXIT_CODE% neq 0 (
    set /A RETRIES+=1
    echo Restarting Genshin Impact...
    timeout /t 15 /nobreak >nul
    goto RETRY
)

endlocal