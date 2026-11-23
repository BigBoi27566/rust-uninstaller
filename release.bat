@echo off
setlocal enabledelayedexpansion

echo ========================================================
echo   Bulk Crap Uninstaller (BCU) - Rust Release Packager
echo ========================================================

set SCRIPT_DIR=%~dp0
set REPO_ROOT=%SCRIPT_DIR%..
set DIST_DIR=%REPO_ROOT%\dist

echo [1/4] Preparing distribution directory: %DIST_DIR%
if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"
mkdir "%DIST_DIR%"

echo [2/4] Compiling all crates in optimized Release mode (LTO + Strip)...
cd /d "%SCRIPT_DIR%"
cargo build --release
if errorlevel 1 (
    echo [ERROR] Cargo release build failed!
    exit /b 1
)

echo [3/4] Copying standalone binaries and licenses to dist/...
copy /y "%SCRIPT_DIR%target\release\bcu-gui.exe" "%DIST_DIR%\bcu-gui.exe" >nul
copy /y "%SCRIPT_DIR%target\release\bcu-cli.exe" "%DIST_DIR%\bcu-cli.exe" >nul
copy /y "%SCRIPT_DIR%target\release\bcu_ffi.dll" "%DIST_DIR%\bcu_ffi.dll" >nul

if exist "%REPO_ROOT%\installer" (
    mkdir "%DIST_DIR%\installer" 2>nul
    copy /y "%REPO_ROOT%\installer\*" "%DIST_DIR%\installer\" >nul
)

if exist "%REPO_ROOT%\Licence.txt" copy /y "%REPO_ROOT%\Licence.txt" "%DIST_DIR%\Licence.txt" >nul
if exist "%REPO_ROOT%\NOTICE" copy /y "%REPO_ROOT%\NOTICE" "%DIST_DIR%\NOTICE" >nul
if exist "%SCRIPT_DIR%README.md" copy /y "%SCRIPT_DIR%README.md" "%DIST_DIR%\README.txt" >nul

echo [4/4] Package assembly complete!
echo.
echo ========================================================
echo   Distribution Artifacts:
echo ========================================================
dir "%DIST_DIR%" /b
echo.
echo All artifacts generated in: %DIST_DIR%
exit /b 0
