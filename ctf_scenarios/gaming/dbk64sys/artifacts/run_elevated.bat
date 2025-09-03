@echo off
echo Running DBK64 test with full administrator privileges...
echo.

REM Try to enable SeDebugPrivilege programmatically
powershell -Command "Add-Type -AssemblyName System.DirectoryServices.AccountManagement; [System.DirectoryServices.AccountManagement.UserPrincipal]::Current.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)" 

echo.
echo Testing DBK64 communication...
C:\Python313\python.exe C:\Analysis\dbk64_debug_structure.py

echo.
echo Testing with explicit privilege adjustment...
C:\Python313\python.exe C:\Analysis\sedebug_current_session.py

pause
