@echo off
REM DBK64 Test Runner - Run all tests to find what works

echo ========================================
echo DBK64 Driver Testing Suite
echo ========================================
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [+] Running as Administrator
) else (
    echo [-] NOT running as Administrator
    echo     Some tests may fail without admin rights!
)
echo.

REM Check if driver is loaded
sc query DBK64 >nul 2>&1
if %errorLevel% == 0 (
    echo [+] DBK64 service exists
    sc query DBK64 | findstr "RUNNING" >nul
    if %errorLevel% == 0 (
        echo [+] DBK64 is RUNNING
    ) else (
        echo [-] DBK64 is NOT running
        echo     Attempting to start...
        sc start DBK64
    )
) else (
    echo [-] DBK64 service not found!
    echo     Please install the driver first
    exit /b 1
)
echo.

REM Run comprehensive test
echo Running comprehensive test...
echo ----------------------------------------
python dbk64_comprehensive_test.py
echo.
echo ----------------------------------------

REM If comprehensive test fails, try individual tests
echo.
echo Running individual tests...
echo.

echo [1] Testing with privileges...
python dbk64_privileged.py
if %errorLevel% == 0 (
    echo     SUCCESS with privileges!
    goto :done
)

echo.
echo [2] Testing with CE exact flags...
python dbk64_ce_exact.py
if %errorLevel% == 0 (
    echo     SUCCESS with CE flags!
    goto :done
)

echo.
echo [3] Testing with overlapped I/O...
python dbk64_overlapped.py
if %errorLevel% == 0 (
    echo     SUCCESS with overlapped!
    goto :done
)

echo.
echo [4] Testing raw approach...
python dbk64_raw_test.py

:done
echo.
echo ========================================
echo Testing complete
echo ========================================
pause