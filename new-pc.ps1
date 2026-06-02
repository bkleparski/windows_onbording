#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Onboarding nowego komputera Windows
    Uruchamiany przez launcher: irm go.ebartnet.pl/onbording | iex
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

$logPath = Join-Path $env:TEMP ("onboarding_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $logPath -ErrorAction SilentlyContinue

function Write-Step {
    param([string]$Text, [int]$Step, [int]$Total)
    Write-Host ""
    Write-Host "  ── KROK $Step/$Total : $Text " -ForegroundColor Cyan
    Write-Host ""
}

function Ask-YesNo {
    param([string]$Question)
    do { $r = Read-Host "  $Question [t/n]" } while ($r.ToLower() -notin @('t','n'))
    return $r.ToLower() -eq 't'
}

# ── 1. PSGallery + Windows Update ───────────────────────────────────────
Write-Step "Windows Update" 1 5
try {
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
    }
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
    }
    Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
    Write-Host "  Szukanie i instalacja aktualizacji (bez restartu)..." -ForegroundColor Yellow
    Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot -ErrorAction Stop
    Write-Host "  Windows Update zakonczone." -ForegroundColor Green
} catch {
    Write-Warning "  Blad Windows Update: $_"
}

# ── 2. Aplikacje winget ─────────────────────────────────────────────
Write-Step "Instalacja aplikacji (winget)" 2 5
$apps = @(
    "7zip.7zip",
    "Adobe.Acrobat.Reader.64-bit",
    "Google.Chrome",
    "Oracle.JavaRuntimeEnvironment",
    "TightVNC.TightVNC",
    "Fortinet.FortiClientVPN"
)

if (Get-Command winget -ErrorAction SilentlyContinue) {
    foreach ($app in $apps) {
        Write-Host "  Instalacja: $app" -ForegroundColor Cyan
        winget install --id $app -e --source winget `
            --accept-package-agreements --accept-source-agreements --silent
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK] $app" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] $app (kod: $LASTEXITCODE)" -ForegroundColor Yellow
        }
    }
} else {
    Write-Warning "  winget niedostepny — pominięto instalację aplikacji."
}

# ── 3. Dolaczenie do domeny AD ──────────────────────────────────────────
Write-Step "Dolaczenie do domeny Active Directory" 3 5
if (Ask-YesNo "Czy chcesz dolaczyc komputer do domeny AD?") {
    $domain = Read-Host "  Podaj nazwe domeny (np. firma.local)"
    if (-not [string]::IsNullOrWhiteSpace($domain)) {
        Write-Host "  Podaj dane konta z uprawnieniami do dolaczenia do domeny:" -ForegroundColor Yellow
        $cred = Get-Credential -Message "Konto AD do dolaczenia do $domain"
        try {
            Add-Computer -DomainName $domain -Credential $cred -Force -ErrorAction Stop
            Write-Host "  [OK] Komputer dolaczony do $domain." -ForegroundColor Green
            Write-Host "  Restart jest wymagany aby zmiany weszly w zycie." -ForegroundColor Yellow
        } catch {
            Write-Warning "  Blad dolaczania do domeny: $_"
        }
    }
} else {
    Write-Host "  Pominieto dolaczanie do domeny." -ForegroundColor DarkGray
}

# ── 4. WinUtil ─────────────────────────────────────────────────────────────
Write-Step "Ravnet WinUtil (zaawansowana konfiguracja)" 4 5
if (Ask-YesNo "Czy chcesz uruchomic WinUtil?") {
    Write-Host "  Uruchamianie WinUtil w nowym oknie (czekam na zamkniecie)..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell.exe" `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"irm go.ebartnet.pl/winutil | iex`"" `
        -Verb RunAs -Wait
    Write-Host "  WinUtil zakonczony." -ForegroundColor Green
} else {
    Write-Host "  Pominieto WinUtil." -ForegroundColor DarkGray
}

# ── 5. Restart ───────────────────────────────────────────────────────────────
Write-Step "Restart systemu" 5 5
Stop-Transcript -ErrorAction SilentlyContinue
Write-Host "  Log zapisany: $logPath" -ForegroundColor DarkGray
Write-Host ""
if (Ask-YesNo "Czy zrestartowac komputer teraz?") {
    Write-Host "  Restart za 10 sekund..." -ForegroundColor Red
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "  Pamietaj o restarcie przed uzyciem komputera w domenie." -ForegroundColor Yellow
}
