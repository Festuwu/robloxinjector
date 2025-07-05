@echo off
echo Building cat.dll...

REM Try to find Visual Studio Build Tools
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        set "VS_PATH=%%i"
    )
)

if defined VS_PATH (
    echo Found Visual Studio at: %VS_PATH%
    call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"
    cl /LD cat.cpp User32.lib
    if %ERRORLEVEL% EQU 0 (
        echo Build successful! cat.dll created.
    ) else (
        echo Build failed with error code %ERRORLEVEL%
    )
) else (
    echo Visual Studio Build Tools not found.
    echo Please install Visual Studio Build Tools with C++ workload.
    echo Download from: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
    pause
) 