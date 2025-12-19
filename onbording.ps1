# =============================================================================
# AUTO-UNLOCK SECTION (To musi być na samym początku!)
# =============================================================================

# 1. Wymuszenie TLS 1.2 (dla pobierania modułów na starszych kompilacjach Win10)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 2. Odblokowanie wykonywania skryptów TYLKO dla obecnego procesu (sesji)
# To sprawia, że Import-Module przestanie sypać błędem "scripts disabled"
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

# 3. Sprawdzenie Admina (bez tego instalacje się nie udadzą)
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "URUCHOM POWERSHELL JAKO ADMINISTRATOR I SPROBUJ PONOWNIE!"
    Start-Sleep -Seconds 5
    Exit
}

Write-Host "--- INICJALIZACJA SRODOWISKA ---" -ForegroundColor Cyan

# 4. Ustawienie zaufania do PSGallery (żeby nie pytał "Untrusted repository")
# To eliminuje błąd/pytanie o "PowerClouds Michal Gajda"
try {
    # Najpierw upewnij się, że mamy dostawcę pakietów
    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
    }
    # Ustaw politykę zaufania
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
} catch {
    Write-Host "Ostrzezenie przy konfiguracji repozytorium (mozna zignorowac jesli instalacja ruszy)" -ForegroundColor DarkGray
}

# =============================================================================
# GLOWNY KOD SETUPU
# =============================================================================

Write-Host "--- START INSTALACJI ---" -ForegroundColor Cyan

# KROK 1: Moduł Windows Update
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "Instalowanie modulu PSWindowsUpdate..."
    # -SkipPublisherCheck jest KLUCZOWE, żeby nie pytał o certyfikat autora
    Install-Module PSWindowsUpdate -Force -Scope CurrentUser -AllowClobber -SkipPublisherCheck
}

# Załadowanie modułu (teraz już zadziała, bo mamy Bypass w Scope Process)
Import-Module PSWindowsUpdate

# KROK 2: Uruchomienie Windows Update
Write-Host "Szukanie i instalacja aktualizacji Windows..." -ForegroundColor Yellow
try {
    Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot
} catch {
    Write-Warning "Blad Windows Update: $_"
}

# KROK 3: WinGet Aplikacje
Write-Host "Instalacja aplikacji..." -ForegroundColor Yellow
$apps = @("7zip.7zip", "Adobe.Acrobat.Reader.64-bit", "Google.Chrome", "Oracle.JavaRuntimeEnvironment", "TightVNC.TightVNC", "Fortinet.FortiClientVPN")

foreach ($app in $apps) {
    Write-Host "WinGet: $app"
    winget install --id $app -e --source winget --accept-package-agreements --accept-source-agreements --silent --force
}

# KROK 4: Czyszczenie Office (Appx)
Write-Host "Czyszczenie bloatware Office..." -ForegroundColor Yellow
Get-AppxPackage -AllUsers | Where-Object { $_.Name -like "*MicrosoftOfficeHub*" -or $_.Name -like "*Office.Desktop*" } | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue

# KROK 5: Restart
Write-Host "RESTART ZA 10 SEKUND!" -ForegroundColor Red
Start-Sleep -Seconds 10
Restart-Computer -Force