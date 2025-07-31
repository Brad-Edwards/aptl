@echo off
set DRIVER=C:\capcom-sys-assets\binaries\Capcom.sys
if not exist "%DRIVER%" (echo [!] Missing %DRIVER% & exit /b 1)
sc create capcom type= kernel start= demand binPath= "%DRIVER%"
sc start capcom
sc query capcom
