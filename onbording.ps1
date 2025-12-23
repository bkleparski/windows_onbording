
# =============================================================================
# ONBOARDING SCRIPT 
# =============================================================================
[CmdletBinding()]
param(
    [switch]$NoReboot,
    [switch]$NonInteractive
)

# 1. Logowanie
$logPath = Join-Path -Path $env:TEMP -ChildPath ("onboarding_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))
Start-Transcript -Path $logPath -ErrorAction SilentlyContinue

# 2. Wymuszenie TLS 1.2 (dla pobierania modulow na starszych kompilacjach Win10)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]:: Tls12

# 3. Odblokowanie wykonywania skryptow TYLKO dla obecnego procesu (sesji)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

function Ensure-Admin {
    # Jeżeli mamy uprawnienia admina — nic nie rób
    if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        return
    }

    # Jeżeli jesteśmy w trybie nieinteraktywnym — nie możemy pokazać UAC, więc zgłoś błąd lub zakończ
    if ($NonInteractive) {
        Write-Warning "Brak uprawnień administratora i tryb nieinteraktywny. Nie moge podnieść uprawnień."
        Stop-Transcript -ErrorAction SilentlyContinue
        Exit 1
    }

    Write-Host "Skrypt nie jest uruchomiony jako administrator. Uruchamiam ponownie z podniesionymi uprawnieniami..." -ForegroundColor Yellow

    # Zakończ transcript przed ponownym uruchomieniem aby uniknac blokady pliku
    Stop-Transcript -ErrorAction SilentlyContinue

    # Znajdz sciezke aktualnego interpretera (powershell.exe lub pwsh.exe)
    try {
        $procPath = (Get-Process -Id $PID -ErrorAction Stop).Path
    } catch {
        # Fallback
        $procPath = "powershell.exe"
    }

    # Sciezka do skryptu
    $scriptPath = $MyInvocation.MyCommand.Definition

    # Zbuduj liste argumentow: -NoProfile -ExecutionPolicy Bypass -File "skrypt" oraz przekazane switch'e/parametry
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$scriptPath`"")

    # Jeżeli chcesz przekazywać przełączniki z oryginalnego uruchomienia, zbuduj je
    if ($PSBoundParameters.ContainsKey('NoReboot')) { $argList += "-NoReboot" }
    if ($PSBoundParameters.ContainsKey('NonInteractive')) { $argList += "-NonInteractive" }

    # Dodatkowe niepozycjonowane argumenty (jeżeli były)
    if ($args.Count -gt 0) {
        foreach ($a in $args) {
            # odpowiednio escape'uj cudzyslowia
            $escaped = $a -replace '"', '\"'
            $argList += "`"$escaped`""
        }
    }

    # Uruchom nowy proces z Verb RunAs (spowoduje UAC)
    try {
        Start-Process -FilePath $procPath -ArgumentList $argList -Verb RunAs -Wait
    } catch {
        Write-Warning "Nie udalo sie uruchomic skryptu z uprawnieniami administratora: $_"
        Exit 1
    }

    # Po uruchomieniu nowego procesu zakoncz obecny
    Exit 0
}

function Ensure-PSGalleryTrusted {
    try {
        if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
        }
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    } catch {
        Write-Host "Ostrzezenie przy konfiguracji repozytorium PSGallery: $_" -ForegroundColor DarkGray
    }
}

function Install-ModuleIfMissing {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Host "Instalowanie modulu $Name..." -ForegroundColor Yellow
        try {
            Install-Module -Name $Name -Force -Scope CurrentUser -AllowClobber -ErrorAction Stop
            Write-Host "Zainstalowano modul $Name" -ForegroundColor Green
        } catch {
            Write-Warning "Nie udalo sie zainstalowac modulu $Name`: $_"
        }
    }
    Import-Module $Name -ErrorAction SilentlyContinue
}

function Install-WinGetApps {
    param([string[]]$Apps)
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Warning "winget nie jest dostepny na tej maszynie. Pomin instalacje aplikacji lub zainstaluj winget."
        return
    }

    foreach ($app in $Apps) {
        Write-Host "WinGet:  $app" -ForegroundColor Cyan
        try {
            $args = @("install", "--id", $app, "-e", "--source", "winget", "--accept-package-agreements", "--accept-source-agreements")
            # dodaj --silent, ale może nie dzialac dla wszystkich pakietow - ignoruj blad (winget zwroci kod)
            $args += "--silent"
            & winget @args
            Write-Host "Zainstalowano:  $app" -ForegroundColor Green
        } catch {
            Write-Warning "Nie udalo sie zainstalowac: $app.  Blad: $_"
        }
    }
}

function Read-Indices {
    param([string]$input, [int]$max)
    $result = @()
    if ([string]::IsNullOrWhiteSpace($input)) { return $result }
    $tokens = $input -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
    foreach ($t in $tokens) {
        if ($t -match '^\d+$') {
            $n = [int]$t
            if ($n -ge 1 -and $n -le $max) {
                $result += ($n - 1)
            }
        }
    }
    return $result
}

# 4. Funkcja uruchamiajaca skrypt Ravnet (winutil) w osobnym oknie PowerShell i czekajaca na jego zakonczenie
function Run-RavnetScript {
    param([string]$Url = "https://raw.githubusercontent.com/bkleparski/winutil/refs/heads/main/winutil.ps1")
    if ($NonInteractive) {
        Write-Host "Tryb nieinteraktywny: pomijam uruchomienie skryptu Ravnet." -ForegroundColor Yellow
        return
    }
    Write-Host "Uruchamiam skrypt Ravnet: $Url (nowe okno PowerShell). Poczekam az narzedzie sie zamknie..." -ForegroundColor Yellow
    try {
        # Argumenty do uruchomienia nowego PowerShell z bypass i wykonaniem pobranego skryptu (uzycie iwr -useb | iex)
        $psArgs = "-NoProfile -ExecutionPolicy Bypass -Command `"iwr -useb '$Url' | iex`""
        Start-Process -FilePath "powershell.exe" -ArgumentList $psArgs -Wait
        Write-Host "Skrypt Ravnet (winutil) zakonczyl dzialanie." -ForegroundColor Green
    } catch {
        Write-Warning "Nie udalo sie uruchomic skryptu Ravnet: $_"
    }
}

# 5. Upewnij sie, ze mamy uprawnienia
Ensure-Admin

Write-Host "--- INICJALIZACJA SRODOWISKA ---" -ForegroundColor Cyan
Ensure-PSGalleryTrusted

Write-Host "--- START INSTALACJI ---" -ForegroundColor Cyan

# 6. Modul Windows Update
Install-ModuleIfMissing -Name "PSWindowsUpdate"

# 7. Uruchomienie Windows Update (bez restartu)
Write-Host "Szukanie i instalacja aktualizacji Windows..." -ForegroundColor Yellow
try {
    if (Get-Command Get-WindowsUpdate -ErrorAction SilentlyContinue) {
        Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot -ErrorAction Stop
        Write-Host "Windows Update zakonczone (bez restartu)" -ForegroundColor Green
    } else {
        Write-Warning "Get-WindowsUpdate nieznaleziony. Modul PSWindowsUpdate nie zaladowal sie poprawnie."
    }
} catch {
    Write-Warning "Blad Windows Update: $_"
}

# 8. WinGet Aplikacje
Write-Host "Instalacja aplikacji (winget)..." -ForegroundColor Yellow
$apps = @("7zip.7zip", "Adobe.Acrobat.Reader. 64-bit", "Google.Chrome", "Oracle.JavaRuntimeEnvironment", "TightVNC.TightVNC", "Fortinet. FortiClientVPN")
Install-WinGetApps -Apps $apps

# 9. Uruchom skrypt Ravnet (winutil) i poczekaj az zostanie zamkniety, potem przejdz do zarzadzania aplikacjami
Run-RavnetScript -Url "https://raw.githubusercontent.com/bkleparski/winutil/refs/heads/main/winutil.ps1"

# 10. Zarzadzanie zainstalowanymi aplikacjami
Write-Host "Sprawdzanie zainstalowanych aplikacji..." -ForegroundColor Yellow

# 11. Pobierz liste zainstalowanych aplikacji (unikalne nazwy) - ogranicz do biezacej listy uzytkownikow
try {
    $installedApps = Get-AppxPackage -AllUsers |
        Select-Object @{Name='DisplayName';Expression={if ($_.Name) { $_.Name } else { $_.PackageFullName }}}, PackageFullName, Name |
        Sort-Object DisplayName -Unique
} catch {
    Write-Warning "Nie udalo sie pobrac listy aplikacji: $_"
    $installedApps = @()
}

$maxApps = 50
$displayApps = $installedApps | Select-Object -First $maxApps
$remainingCount = $installedApps.Count - $maxApps

Write-Host "Zainstalowane aplikacje (pierwsze $maxApps z $($installedApps.Count)):" -ForegroundColor Cyan
for ($i = 0; $i -lt $displayApps.Count; $i++) {
    Write-Host "$('{0,2}' -f ($i + 1)). $($displayApps[$i]. DisplayName)" -ForegroundColor White
}
if ($remainingCount -gt 0) {
    Write-Host " ... i $remainingCount wiecej aplikacji" -ForegroundColor DarkGray
}

if (-not $NonInteractive) {
    do {
        Write-Host "Podaj numery aplikacji do usuniecia oddzielone przecinkami (0 aby zakonczyc): " -ForegroundColor Yellow -NoNewline
        $selection = Read-Host

        if ($selection -eq "0") {
            Write-Host "Pomijanie usuwania aplikacji. Przechodzenie dalej..." -ForegroundColor Green
            break
        }

        $indices = Read-Indices -input $selection -max $displayApps.Count

        if ($indices.Count -eq 0) {
            Write-Host "Brak poprawnych numerow.  Sprobuj ponownie." -ForegroundColor Red
        } else {
            foreach ($index in $indices) {
                $appToRemove = $displayApps[$index]
                Write-Host "Usuwanie aplikacji: $($appToRemove.DisplayName) (PackageFullName: $($appToRemove.PackageFullName))" -ForegroundColor Yellow
                try {
                    # Sprobuj usunac pakiet dla biezacego uzytkownika
                    Remove-AppxPackage -Package $appToRemove.PackageFullName -ErrorAction Stop
                    Write-Host "Aplikacja $($appToRemove. DisplayName) zostala pomyslnie usunieta dla biezacego uzytkownika." -ForegroundColor Green
                } catch {
                    Write-Warning "Nie udalo sie usunac aplikacji jako obecny uzytkownik: $_"
                    # Sprobuj usunac pakiet provisioned (dla przyszlych uzytkownikow) - wymaga nazwy paczki (Name)
                    if ($appToRemove.Name) {
                        try {
                            Remove-AppxProvisionedPackage -Online -PackageName $appToRemove.Name -ErrorAction Stop
                            Write-Host "Usunieto pakiet provisioned ($($appToRemove.Name)) z obrazu systemu (dla nowych uzytkownikow)." -ForegroundColor Green
                        } catch {
                            Write-Warning "Nie udalo sie usunac pakietu provisioned ($($appToRemove.Name)): $_"
                        }
                    }
                }
            }
        }

        Write-Host "Czy chcesz usunac wiecej aplikacji? (t/n): " -ForegroundColor Yellow -NoNewline
        $continue = Read-Host
    } while ($continue -eq "t" -or $continue -eq "T")
} else {
    Write-Host "Tryb nieinteraktywny:  pomijam czesc dotyczaca recznego usuwania aplikacji." -ForegroundColor Yellow
}

# 12. Restart (potwierdzenie lub rezygnacja)
if ($NoReboot) {
    Write-Host "Parametr -NoReboot ustawiony.  Pomijam restart." -ForegroundColor Cyan
} else {
    if ($NonInteractive) {
        Write-Host "Tryb nieinteraktywny: restart zostanie wykonany za 10 sekund." -ForegroundColor Red
        Start-Sleep -Seconds 10
        try {
            Restart-Computer -Force
        } catch {
            Write-Warning "Restart nie powiodl sie: $_"
        }
    } else {
        # Interaktywny: zapytaj uzytkownika czy zrestartowac
        do {
            $response = Read-Host "Czy chcesz zrestartowac komputer teraz? (t/n)"
            switch ($response.ToLower()) {
                't' {
                    Write-Host "Restart zostanie wykonany za 10 sekund. Przerwij skrypt, jesli chcesz anulowac." -ForegroundColor Red
                    Start-Sleep -Seconds 10
                    try {
                        Restart-Computer -Force
                    } catch {
                        Write-Warning "Restart nie powiodl sie: $_"
                    }
                    break
                }
                'n' {
                    Write-Host "Anulowano restart. Mozesz zrestartowac recznie pozniej." -ForegroundColor Cyan
                    break
                }
                default {
                    Write-Host "Nieprawidlowy wybor. Wpisz 't' aby potwierdzic restart lub 'n' aby zrezygnowac." -ForegroundColor Yellow
                }
            }
        } while ($true)
    }
}

Stop-Transcript -ErrorAction SilentlyContinue
Write-Host "Log zapisany w: $logPath" -ForegroundColor Cyan
