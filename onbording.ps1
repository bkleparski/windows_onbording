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
    try {
        winget install --id $app -e --source winget --accept-package-agreements --accept-source-agreements --silent --force
        Write-Host "Zainstalowano: $app" -ForegroundColor Green
    } catch {
        Write-Warning "Nie udało się zainstalować: $app"
    }
}

# KROK 4: Zarządzanie zainstalowanymi aplikacjami
Write-Host "Sprawdzanie zainstalowanych aplikacji..." -ForegroundColor Yellow

# Pobierz listę zainstalowanych aplikacji (unikalne nazwy)
$installedApps = Get-AppxPackage -AllUsers | 
    Select-Object Name, PackageFullName | 
    Sort-Object Name -Unique

# Wyświetl aplikacje w punktach z numeracją (maks. 50)
$maxApps = 50
$displayApps = $installedApps | Select-Object -First $maxApps
$remainingCount = $installedApps.Count - $maxApps

Write-Host "Zainstalowane aplikacje (pierwsze $maxApps z $($installedApps.Count)):" -ForegroundColor Cyan
for ($i = 0; $i -lt $displayApps.Count; $i++) {
    Write-Host "$('{0,2}' -f ($i + 1)). $($displayApps[$i].Name)" -ForegroundColor White
}

if ($remainingCount -gt 0) {
    Write-Host " ... i $remainingCount więcej aplikacji" -ForegroundColor DarkGray
}

# Zapytaj użytkownika, czy chce coś usunąć (możliwość wielokrotnego wyboru)
do {
    Write-Host "Podaj numery aplikacji do usunięcia oddzielone przecinkami (0 aby zakończyć): " -ForegroundColor Yellow -NoNewline
    $selection = Read-Host
    
    if ($selection -eq "0") {
        Write-Host "Pomijanie usuwania aplikacji. Przechodzenie do kroku 5..." -ForegroundColor Green
        break
    }
    
    # Parsowanie wielu numerów
    $indices = $selection -split ',' | ForEach-Object { [int]$_ - 1 }
    $validIndices = @()
    $invalidIndices = @()
    
    foreach ($index in $indices) {
        if ($index -ge 0 -and $index -lt $displayApps.Count) {
            $validIndices += $index
        } else {
            $invalidIndices += $index + 1
        }
    }
    
    if ($invalidIndices.Count -gt 0) {
        Write-Host "Nieprawidłowe numery: $($invalidIndices -join ', ')" -ForegroundColor Red
    }
    
    if ($validIndices.Count -gt 0) {
        foreach ($index in $validIndices) {
            $appToRemove = $displayApps[$index]
            try {
                Write-Host "Usuwanie aplikacji: $($appToRemove.Name)" -ForegroundColor Yellow
                Remove-AppxPackage -Package $appToRemove.PackageFullName -AllUsers -ErrorAction Stop
                Write-Host "Aplikacja $($appToRemove.Name) została pomyślnie usunięta." -ForegroundColor Green
            } catch {
                Write-Host "Wystąpił błąd podczas usuwania aplikacji $($appToRemove.Name): $_" -ForegroundColor Red
            }
        }
    }
    
    # Zapytaj czy usunąć więcej
    Write-Host "Czy chcesz usunąć więcej aplikacji? (t/n): " -ForegroundColor Yellow -NoNewline
    $continue = Read-Host
} while ($continue -eq "t" -or $continue -eq "T")

# KROK 5: Restart
Write-Host "RESTART ZA 10 SEKUND!" -ForegroundColor Red
Start-Sleep -Seconds 10
Restart-Computer -Force
