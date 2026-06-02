#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Czyszczenie komputera przed oddaniem nowemu uzytkownikowi
    Uruchamiany przez launcher: irm go.ebartnet.pl/onbording | iex
#>

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

function Write-Step {
    param([string]$Text, [int]$Step, [int]$Total)
    Write-Host ""
    Write-Host "  ── KROK $Step/$Total : $Text " -ForegroundColor Magenta
    Write-Host ""
}

function Ask-YesNo {
    param([string]$Question)
    do { $r = Read-Host "  $Question [t/n]" } while ($r.ToLower() -notin @('t','n'))
    return $r.ToLower() -eq 't'
}

function Get-FolderSizeMB {
    param([string]$Path)
    try {
        $bytes = (Get-ChildItem $Path -Recurse -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        return [math]::Round($bytes / 1MB, 1)
    } catch { return 0 }
}

function Remove-FolderContents {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path $Path)) { return }
    $mb = Get-FolderSizeMB $Path
    Remove-Item "$Path\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host ("  [OK] {0,-28} (-{1} MB)" -f $Label, $mb) -ForegroundColor Green
    return $mb
}

Clear-Host
Write-Host ""
Write-Host "  ╔═════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║   Czyszczenie komputera — przed oddaniem       ║" -ForegroundColor Magenta
Write-Host "  ╚═════════════════════════════════════════════╝" -ForegroundColor Magenta

# ── KROK 0: SYSPREP ──────────────────────────────────────────────────────────
Write-Step "Reset do stanu fabrycznego (Sysprep)" 0 5
Write-Host "  UWAGA: Sysprep usunie WSZYSTKIE dane, konta uzytkownikow," -ForegroundColor Red
Write-Host "  aplikacje i ustawienia. System uruchomi sie jak nowy komputer." -ForegroundColor Red
Write-Host ""
if (Ask-YesNo "Wykonac SYSPREP (usunie WSZYSTKO bezpowrotnie)?") {
    Write-Host ""
    Write-Host "  OSTATNIE OSTRZEZENIE: wszystkie dane zostana trwale usuniete." -ForegroundColor Red
    if (Ask-YesNo "  Na pewno kontynuowac?") {
        Write-Host "  Uruchamianie Sysprep... system wylaczy sie automatycznie." -ForegroundColor Red
        Start-Sleep -Seconds 3
        Start-Process -FilePath "C:\Windows\System32\Sysprep\sysprep.exe" `
            -ArgumentList "/oobe /generalize /shutdown" -Wait
        exit 0
    }
}
Write-Host "  Pominieto Sysprep. Przechodze do recznego czyszczenia..." -ForegroundColor DarkGray

# ── KROK 1: PROFILE UZYTKOWNIKOW ───────────────────────────────────────────────
Write-Step "Profile uzytkownikow" 1 5
$currentUser = $env:USERNAME
$profiles = Get-CimInstance -ClassName Win32_UserProfile |
    Where-Object { -not $_.Special -and $_.LocalPath -notmatch "\\$currentUser$" }

if ($profiles.Count -eq 0) {
    Write-Host "  Brak dodatkowych profili do usuniecia." -ForegroundColor DarkGray
} else {
    Write-Host "  Profile uzytkownikow (poza aktualnym '$currentUser'):" -ForegroundColor Yellow
    $profiles | ForEach-Object { Write-Host "    • $($_.LocalPath)" -ForegroundColor White }
    Write-Host ""
    if (Ask-YesNo "Usunac wszystkie wymienione profile?") {
        foreach ($p in $profiles) {
            try {
                Remove-CimInstance -InputObject $p -ErrorAction Stop
                Write-Host "  [OK] Usunieto: $($p.LocalPath)" -ForegroundColor Green
            } catch {
                Write-Warning "  Blad $($p.LocalPath): $_"
            }
        }
    } else {
        Write-Host "  Pominieto usuwanie profili." -ForegroundColor DarkGray
    }
}

# ── KROK 2: CZYSZCZENIE ──────────────────────────────────────────────────────────
Write-Step "Czyszczenie plikow tymczasowych i cache" 2 5
$totalFreed = 0

$totalFreed += Remove-FolderContents "C:\Windows\Temp"           "Temp systemowy"
$totalFreed += Remove-FolderContents $env:TEMP                  "Temp uzytkownika"
$totalFreed += Remove-FolderContents "C:\Windows\Prefetch"      "Prefetch"
$totalFreed += Remove-FolderContents "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache" "Chrome cache"
$totalFreed += Remove-FolderContents "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache" "Edge cache"

# Kosz
Clear-RecycleBin -Force -ErrorAction SilentlyContinue
Write-Host "  [OK] Kosz oprózniony" -ForegroundColor Green

# Windows Update cache
try {
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    $wuPath = "C:\Windows\SoftwareDistribution\Download"
    $totalFreed += Remove-FolderContents $wuPath "WU Download cache"
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
} catch {}

# DISM
Write-Host "  Czyszczenie komponentow Windows (DISM)..." -ForegroundColor Yellow
Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1 | Out-Null
Write-Host "  [OK] DISM zakonczone" -ForegroundColor Green

Write-Host ""
Write-Host "  Lacznie zwolniono ok. $([math]::Round($totalFreed,1)) MB" -ForegroundColor Cyan

# ── KROK 3: APLIKACJE ───────────────────────────────────────────────────────────
Write-Step "Dezinstalacja aplikacji" 3 5
if (Ask-YesNo "Czy chcesz odinstalowac aplikacje?") {
    Write-Host "  Pobieranie listy aplikacji z rejestru..." -ForegroundColor Yellow
    $regPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $pkgs = Get-ItemProperty -Path $regPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.UninstallString } |
        Sort-Object DisplayName |
        Select-Object DisplayName, DisplayVersion, UninstallString -Unique

    if ($pkgs.Count -eq 0) {
        Write-Host "  Brak aplikacji w rejestrze." -ForegroundColor DarkGray
    } else {
        Write-Host ""
        for ($i = 0; $i -lt $pkgs.Count; $i++) {
            Write-Host ("  [{0,3}] {1} ({2})" -f ($i + 1), $pkgs[$i].DisplayName, $pkgs[$i].DisplayVersion) -ForegroundColor White
        }
        Write-Host ""
        Write-Host "  [  0] Odinstaluj WSZYSTKIE" -ForegroundColor Red
        Write-Host ""
        $sel = Read-Host "  Podaj numery oddzielone przecinkami (lub Enter aby pominac)"

        if (-not [string]::IsNullOrWhiteSpace($sel)) {
            if ($sel.Trim() -eq '0') {
                $toRemove = $pkgs
            } else {
                $indices = $sel -split ',' |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { $_ -match '^\d+$' } |
                    ForEach-Object { [int]$_ - 1 } |
                    Where-Object { $_ -ge 0 -and $_ -lt $pkgs.Count }
                $toRemove = @($pkgs[$indices])
            }

            foreach ($app in $toRemove) {
                if (-not $app) { continue }
                Write-Host "  Usuwanie: $($app.DisplayName)..." -ForegroundColor Cyan
                try {
                    $cmd = $app.UninstallString
                    if ($cmd -match 'MsiExec') {
                        $code = [regex]::Match($cmd, '\{[A-Z0-9-]+\}').Value
                        Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $code /qn /norestart" -Wait -ErrorAction Stop
                    } else {
                        # Próba cichej dezinstalacji
                        $cleanCmd = $cmd.Trim('"')
                        Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$cmd`" /S /VERYSILENT /quiet" -Wait -ErrorAction Stop
                    }
                    Write-Host "  [OK] $($app.DisplayName)" -ForegroundColor Green
                } catch {
                    Write-Warning "  Nie udalo sie usunac: $($app.DisplayName) — $($_.Exception.Message)"
                }
            }
        }
    }
} else {
    Write-Host "  Pominieto dezinstalacje." -ForegroundColor DarkGray
}

# ── KROK 4: HARMONOGRAM I AUTOSTART ─────────────────────────────────────────────
Write-Step "Harmonogram zadan i autostart" 4 5
if (Ask-YesNo "Czy chcesz wyczyścic harmonogram zadan i autostart?") {

    # Harmonogram — tylko niestandardowe zadania
    Write-Host "  Niestandardowe zadania harmonogramu:" -ForegroundColor Yellow
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
        Sort-Object TaskName

    if ($tasks.Count -eq 0) {
        Write-Host "  Brak niestandardowych zadan." -ForegroundColor DarkGray
    } else {
        for ($i = 0; $i -lt $tasks.Count; $i++) {
            Write-Host ("  [{0,3}] {1}{2}" -f ($i + 1), $tasks[$i].TaskPath, $tasks[$i].TaskName) -ForegroundColor White
        }
        Write-Host ""
        $sel = Read-Host "  Numery do usuniecia (lub Enter aby pominac)"
        if (-not [string]::IsNullOrWhiteSpace($sel)) {
            $indices = $sel -split ',' |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -match '^\d+$' } |
                ForEach-Object { [int]$_ - 1 } |
                Where-Object { $_ -ge 0 -and $_ -lt $tasks.Count }
            foreach ($idx in $indices) {
                try {
                    Unregister-ScheduledTask -TaskName $tasks[$idx].TaskName `
                        -TaskPath $tasks[$idx].TaskPath -Confirm:$false -ErrorAction Stop
                    Write-Host "  [OK] Usunieto: $($tasks[$idx].TaskName)" -ForegroundColor Green
                } catch {
                    Write-Warning "  Blad: $_"
                }
            }
        }
    }

    # Autostart — rejestr
    Write-Host ""
    Write-Host "  Wpisy autostartu (rejestr):" -ForegroundColor Yellow
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    $startupItems = @()
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            $vals = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            $vals.PSObject.Properties |
                Where-Object { $_.Name -notmatch '^PS' } |
                ForEach-Object {
                    $startupItems += [PSCustomObject]@{
                        Key   = $key
                        Name  = $_.Name
                        Value = $_.Value
                    }
                }
        }
    }

    if ($startupItems.Count -eq 0) {
        Write-Host "  Brak wpisów autostartu." -ForegroundColor DarkGray
    } else {
        for ($i = 0; $i -lt $startupItems.Count; $i++) {
            Write-Host ("  [{0,3}] {1}  =  {2}" -f ($i + 1), $startupItems[$i].Name, $startupItems[$i].Value) -ForegroundColor White
        }
        Write-Host ""
        $sel = Read-Host "  Numery do usuniecia (lub Enter aby pominac)"
        if (-not [string]::IsNullOrWhiteSpace($sel)) {
            $indices = $sel -split ',' |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -match '^\d+$' } |
                ForEach-Object { [int]$_ - 1 } |
                Where-Object { $_ -ge 0 -and $_ -lt $startupItems.Count }
            foreach ($idx in $indices) {
                try {
                    Remove-ItemProperty -Path $startupItems[$idx].Key `
                        -Name $startupItems[$idx].Name -Force -ErrorAction Stop
                    Write-Host "  [OK] Usunieto: $($startupItems[$idx].Name)" -ForegroundColor Green
                } catch {
                    Write-Warning "  Blad: $_"
                }
            }
        }
    }
} else {
    Write-Host "  Pominieto harmonogram i autostart." -ForegroundColor DarkGray
}

# ── KROK 5: RESET PRZEGLADAREK ──────────────────────────────────────────────────
Write-Step "Reset przegladarek do ustawien domyslnych" 5 5
if (Ask-YesNo "Czy chcesz zresetowac Chrome i Edge do domyslnych?") {

    # Chrome
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    if (Test-Path $chromePath) {
        Get-Process -Name "chrome" -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 1
        Remove-Item $chromePath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] Chrome — profil usuniety (reset do domyslnych)" -ForegroundColor Green
    } else {
        Write-Host "  Chrome nie znaleziony lub brak profilu." -ForegroundColor DarkGray
    }

    # Edge
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
    if (Test-Path $edgePath) {
        Get-Process -Name "msedge" -ErrorAction SilentlyContinue | Stop-Process -Force
        Start-Sleep -Seconds 1
        Remove-Item $edgePath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] Edge — profil usuniety (reset do domyslnych)" -ForegroundColor Green
    } else {
        Write-Host "  Edge nie znaleziony lub brak profilu." -ForegroundColor DarkGray
    }

} else {
    Write-Host "  Pominieto reset przegladarek." -ForegroundColor DarkGray
}

# ── KONIEC ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔═════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║   Czyszczenie zakonczone. Komputer gotowy.   ║" -ForegroundColor Green
Write-Host "  ╚═════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Zalecany restart przed oddaniem komputera nowemu uzytkownikowi." -ForegroundColor Yellow
Write-Host ""
if (Ask-YesNo "Zrestartowac teraz?") {
    Write-Host "  Restart za 10 sekund..." -ForegroundColor Red
    Start-Sleep -Seconds 10
    Restart-Computer -Force
}
