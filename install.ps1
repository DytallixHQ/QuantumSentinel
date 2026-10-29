$ErrorActionPreference = "Stop"

$RepositoryUrl = if ($env:QS_REPOSITORY_URL) { $env:QS_REPOSITORY_URL } else { "https://github.com/DytallixHQ/QuantumSentinel.git" }
$InstallDirectory = if ($env:QS_INSTALL_DIR) { $env:QS_INSTALL_DIR } else { Join-Path (Get-Location) "QuantumSentinel" }

function Write-Step {
  param([string]$Message)
  Write-Host $Message
}

function Stop-Setup {
  param([string]$Message)
  Write-Error "Quantum Sentinel setup stopped: $Message"
  exit 1
}

function Test-Command {
  param([string]$Name)
  return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

if (-not (Test-Command "git")) {
  Stop-Setup "Git is required. Install Git and run this command again."
}

if (-not (Test-Command "node")) {
  Stop-Setup "Node.js 20.19 or newer is required: https://nodejs.org/"
}

if (-not (Test-Command "npm")) {
  Stop-Setup "npm is required and normally ships with Node.js."
}

$NodeVersion = node -p "process.versions.node"
$NodeParts = $NodeVersion.Split(".")
$NodeMajor = [int]$NodeParts[0]
$NodeMinor = [int]$NodeParts[1]

if ($NodeMajor -lt 20 -or ($NodeMajor -eq 20 -and $NodeMinor -lt 19)) {
  Stop-Setup "Node.js 20.19 or newer is required. Current version: v$NodeVersion"
}

$GitDirectory = Join-Path $InstallDirectory ".git"

if (Test-Path $GitDirectory) {
  $CurrentRemote = git -C $InstallDirectory remote get-url origin 2>$null
  if ($CurrentRemote -ne $RepositoryUrl) {
    Stop-Setup "$InstallDirectory is a different Git repository. Set QS_INSTALL_DIR to another location."
  }

  Write-Step "Updating Quantum Sentinel in $InstallDirectory..."
  git -C $InstallDirectory pull --ff-only
} elseif (Test-Path $InstallDirectory) {
  Stop-Setup "$InstallDirectory already exists and is not a Quantum Sentinel checkout. Set QS_INSTALL_DIR to another location."
} else {
  Write-Step "Downloading Quantum Sentinel to $InstallDirectory..."
  git clone --depth 1 $RepositoryUrl $InstallDirectory
}

Write-Step "Installing dependencies and building the dashboard..."
Set-Location $InstallDirectory
npm ci --no-audit --no-fund
npm run build

Write-Step "Quantum Sentinel installation is complete."
if ($env:QS_INSTALL_ONLY -eq "1") {
  Write-Step "Start it later with: cd `"$InstallDirectory`"; npm start"
  exit 0
}

npm start
