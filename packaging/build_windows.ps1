# Build the Dynascan desktop app and installer on Windows.
# Prereqs: Python 3.10+ on PATH; Inno Setup 6 (iscc.exe) for the installer step.
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

python -m venv .venv-build
.\.venv-build\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[gui,build]"

pyinstaller packaging\dynascan.spec --noconfirm --distpath dist --workpath build

if (Get-Command iscc -ErrorAction SilentlyContinue) {
    iscc packaging\installer.iss
    Write-Host "Installer: installer-out\Dynascan-Setup-*.exe"
} else {
    Write-Host "Inno Setup (iscc) not found - portable app is in dist\Dynascan\Dynascan.exe"
}
