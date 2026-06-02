#Requires -RunAsAdministrator
<#
.SYNOPSIS Onboarding nowego komputera Windows
#>

$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

$logPath = "$env:USERPROFILE\Desktop\NewPC_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)
Start-Transcript -Path $logPath -ErrorAction SilentlyContinue
Write-Host "  Log: $logPath" -ForegroundColor DarkGray

function Write-Step {
    param([string]$Text, [int]$Step, [int]$Total)
    Write-Host ""
    Write-Host "  " + ("-" * 55) -ForegroundColor DarkCyan
    Write-Host "  KROK $Step/$Total : $Text" -ForegroundColor Cyan
    Write-Host "  " + ("-" * 55) -ForegroundColor DarkCyan
    Write-Host ""
}

function Write-OK   { param([string]$T); Write-Host "  [OK]   $T" -ForegroundColor Green }
function Write-WARN { param([string]$T); Write-Host "  [WARN] $T" -ForegroundColor Yellow }
function Write-ERR  { param([string]$T); Write-Host "  [ERR]  $T" -ForegroundColor Red }

function Ask-YesNo {
    param([string]$Question)
    do { $r = Read-Host "  $Question [t/n]" } while ($r.ToLower() -notin @('t','n'))
    return $r.ToLower() -eq 't'
}

function Pause-OnError {
    Write-Host "  Nacisnij Enter aby kontynuowac..." -ForegroundColor DarkGray
    $null = Read-Host
}

# ── 1. Windows Update ────────────────────────────────────────────────────────────
Write-Step "Windows Update" 1 5
try {
    Write-Host "  Konfiguracja PSGallery..." -ForegroundColor Yellow
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        Write-OK "NuGet zainstalowany"
    }
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue

    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Host "  Instalacja modulu PSWindowsUpdate..." -ForegroundColor Yellow
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
        Write-OK "PSWindowsUpdate zainstalowany"
    }
    Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue

    Write-Host "  Szukanie aktualizacji (to moze potrwac kilka minut)..." -ForegroundColor Yellow
    $updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
    if ($updates.Count -gt 0) {
        Write-Host "  Instalacja $($updates.Count) aktualizacji..." -ForegroundColor Yellow
        Install-WindowsUpdate -AcceptAll -IgnoreReboot -ErrorAction Stop
        Write-OK "Windows Update zakonczone ($($updates.Count) aktualizacji)"
    } else {
        Write-OK "Brak nowych aktualizacji"
    }
} catch {
    Write-ERR "Windows Update: $_"
    Pause-OnError
}

# ── 2. Aplikacje winget ───────────────────────────────────────────────────────────
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
        Write-Host "  Instalacja: $app ..." -ForegroundColor Cyan
        try {
            $result = winget install --id $app -e --source winget `
                --accept-package-agreements --accept-source-agreements --silent 2>&1
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1978335135) {
                Write-OK "$app"
            } else {
                Write-WARN "$app (kod: $LASTEXITCODE)"
                Write-Host "  $result" -ForegroundColor DarkGray
            }
        } catch {
            Write-ERR "$app : $_"
        }
    }
} else {
    Write-ERR "winget niedostepny. Zainstaluj App Installer ze sklepu Microsoft."
    Pause-OnError
}

# ── 3. Dolaczenie do domeny AD ─────────────────────────────────────────────
Write-Step "Dolaczenie do domeny Active Directory" 3 5
if (Ask-YesNo "Czy chcesz dolaczyc komputer do domeny AD?") {
    $domain = Read-Host "  Podaj nazwe domeny (np. firma.local)"
    if (-not [string]::IsNullOrWhiteSpace($domain)) {
        Write-Host "  Podaj dane konta z uprawnieniami do dolaczenia do domeny:" -ForegroundColor Yellow
        try {
            $cred = Get-Credential -Message "Konto AD do dolaczenia do $domain"
            Add-Computer -DomainName $domain -Credential $cred -Force -ErrorAction Stop
            Write-OK "Dolaczono do domeny $domain. Restart wymagany."
        } catch {
            Write-ERR "Blad dolaczania do domeny: $_"
            Pause-OnError
        }
    } else {
        Write-WARN "Nie podano nazwy domeny — pominieto."
    }
} else {
    Write-Host "  Pominieto dolaczanie do domeny." -ForegroundColor DarkGray
}

# ── 4. WinUtil ─────────────────────────────────────────────────────────────
Write-Step "Ravnet WinUtil" 4 5
if (Ask-YesNo "Czy chcesz uruchomic WinUtil (zaawansowana konfiguracja)?") {
    Write-Host "  Uruchamianie WinUtil w nowym oknie (poczekaj az zamkniesz to okno)..." -ForegroundColor Yellow
    try {
        Start-Process -FilePath "powershell.exe" `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"irm go.ebartnet.pl/winutil | iex`"" `
            -Verb RunAs -Wait
        Write-OK "WinUtil zakonczony"
    } catch {
        Write-ERR "Blad uruchamiania WinUtil: $_"
        Pause-OnError
    }
} else {
    Write-Host "  Pominieto WinUtil." -ForegroundColor DarkGray
}

# ── 5. Restart ───────────────────────────────────────────────────────────────
Write-Step "Podsumowanie i restart" 5 5
Stop-Transcript -ErrorAction SilentlyContinue
Write-Host "  Log zapisany: $logPath" -ForegroundColor Green
Write-Host ""
if (Ask-YesNo "Czy zrestartowac komputer teraz?") {
    Write-Host "  Restart za 10 sekund... Ctrl+C aby anulowac." -ForegroundColor Red
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "  Pamietaj o restarcie (szczegolnie po dolaczeniu do domeny)." -ForegroundColor Yellow
}
