# scripts\install.ps1
# SpiderForge installer for Windows (PowerShell 5.1+ / 7+)

$ErrorActionPreference = "Stop"
$AppName = "spiderforge"

function Write-Log  { param($Msg) Write-Host "[$AppName] $Msg" -ForegroundColor Cyan }
function Write-Ok   { param($Msg) Write-Host "[OK] $Msg" -ForegroundColor Green }
function Write-Warn { param($Msg) Write-Host "[!] $Msg" -ForegroundColor Yellow }
function Write-Die  { param($Msg) Write-Host "[X] $Msg" -ForegroundColor Red; exit 1 }

Write-Host @"
    ███████╗██████╗ ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
    ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
    ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
    ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██╔══██║██║   ██║██╔══╝
    ███████║██║     ██║██████╔╝███████╗██║  ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
    ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
"@ -ForegroundColor Red

$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
if (-not $py) { Write-Die "Python not found. Install Python 3.10+ from python.org" }

$pyVersion = & $py.Source --version 2>&1
Write-Log "Found: $pyVersion"

$verOk = & $py.Source -c "import sys; sys.exit(0 if sys.version_info[:2] >= (3,10) else 1)"
if ($LASTEXITCODE -ne 0) { Write-Die "Python 3.10+ required" }
Write-Ok "Python version OK"

$pipx = Get-Command pipx -ErrorAction SilentlyContinue
if (-not $pipx) {
    Write-Warn "pipx not found - installing via pip..."
    & $py.Source -m pip install --user --upgrade pipx
    if ($LASTEXITCODE -ne 0) { Write-Die "Failed to install pipx" }

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $scriptsPath = "$env:APPDATA\Python\Scripts"
    if ($userPath -notlike "*$scriptsPath*") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$scriptsPath", "User")
    }
    $env:Path = "$env:Path;$scriptsPath"

    & $py.Source -m pipx ensurepath
    Write-Ok "pipx installed"
} else {
    Write-Ok "pipx available: $(& pipx --version)"
}

$repoDir = (Get-Item $PSScriptRoot).Parent.FullName
Write-Log "Installing SpiderForge from $repoDir..."
Push-Location $repoDir
try {
    pipx install --force .
    if ($LASTEXITCODE -ne 0) { Write-Die "spiderforge install failed" }
    Write-Ok "spiderforge installed"
} finally {
    Pop-Location
}

$web = Read-Host "[?] Install Web Dashboard (fastapi + uvicorn)? [y/N]"
if ($web -match '^[Yy]') {
    pipx inject spiderforge fastapi "uvicorn[standard]"
    Write-Ok "Web Dashboard ready"
}

$pdf = Read-Host "[?] Install PDF export (weasyprint)? [y/N]"
if ($pdf -match '^[Yy]') {
    Write-Warn "WeasyPrint on Windows needs GTK libraries."
    Write-Host "  Download: https://github.com/tschoonj/GTK-for-Windows-Runtime-Installer/raw/main/GTK3-Runtime-Installer.exe" -ForegroundColor Yellow
    pipx inject spiderforge weasyprint
    Write-Ok "PDF export installed (may need GTK)"
}

$dataDir = "$env:USERPROFILE\.spiderforge"
$configDir = "$env:USERPROFILE\.config\spiderforge"
New-Item -ItemType Directory -Force -Path "$dataDir\workspaces" | Out-Null
New-Item -ItemType Directory -Force -Path "$dataDir\logs" | Out-Null
New-Item -ItemType Directory -Force -Path "$configDir" | Out-Null
Write-Ok "Created $dataDir and $configDir"

$cfg = "$configDir\config.yaml"
if (-not (Test-Path $cfg)) {
    @"
scanner:
  concurrency: 20
  timeout: 20.0
  max_depth: 5
  aggressive: false
recon:
  subdomains: true
  ports: false
  technologies: true
browser:
  enabled: false
  screenshots: false
reporting:
  enable_json: true
  enable_html: true
  enable_markdown: true
  enable_pdf: false
logging:
  level: INFO
"@ | Out-File -FilePath $cfg -Encoding UTF8
    Write-Ok "Wrote default config to $cfg"
}

Write-Host ""
Write-Log "Running pre-flight health check..."
$spiderforge = Get-Command spiderforge -ErrorAction SilentlyContinue
if ($spiderforge) {
    spiderforge doctor
} else {
    Write-Warn "spiderforge not on PATH yet. Restart PowerShell or run:"
    Write-Host "  `$env:Path += `";`$env:APPDATA\Python\Scripts`"" -ForegroundColor Cyan
}

Write-Host ""
Write-Ok "Installation complete!"
Write-Host "Run: spiderforge" -ForegroundColor Green