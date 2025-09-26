@echo off
setlocal enabledelayedexpansion

REM Switch to the target directory
cd /d "D:\Program Files\modifyingFirewall\"

REM Create log directory (if not exists)
if not exist "logs\" mkdir logs

REM Generate timestamp log file name
for /f "tokens=2 delims==" %%a in ('wmic os get localdatetime /value ^| findstr "LocalDateTime"') do set "datetime=%%a"
set "logfile=logs\execution_!datetime:~0,8!_!datetime:~8,6!.log"

REM Execute program and record log
echo [Start Time] !date! !time! >> "!logfile!"
modifyingSecurityGroup.exe --minRequiredIPs 1 --maxRequiredIPs 1>> "!logfile!" 2>&1
echo [End Time] !date! !time! >> "!logfile!"