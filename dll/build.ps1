Write-Host "Building cat.dll..." -ForegroundColor Green

# Try to find Visual Studio Build Tools
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    $vswhere = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\vswhere.exe"
}

if (Test-Path $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    
    if ($vsPath) {
        Write-Host "Found Visual Studio at: $vsPath" -ForegroundColor Yellow
        
        $vcvarsPath = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
        if (Test-Path $vcvarsPath) {
            Write-Host "Setting up Visual Studio environment..." -ForegroundColor Yellow
            
            # Call vcvars64.bat and then compile
            cmd /c "`"$vcvarsPath`" && cl /LD cat.cpp User32.lib"
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Build successful! cat.dll created." -ForegroundColor Green
            } else {
                Write-Host "Build failed with error code $LASTEXITCODE" -ForegroundColor Red
            }
        } else {
            Write-Host "vcvars64.bat not found at: $vcvarsPath" -ForegroundColor Red
        }
    } else {
        Write-Host "Visual Studio Build Tools not found." -ForegroundColor Red
        Write-Host "Please install Visual Studio Build Tools with C++ workload." -ForegroundColor Yellow
        Write-Host "Download from: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022" -ForegroundColor Cyan
    }
} else {
    Write-Host "vswhere.exe not found. Visual Studio may not be installed." -ForegroundColor Red
    Write-Host "Please install Visual Studio Build Tools." -ForegroundColor Yellow
} 