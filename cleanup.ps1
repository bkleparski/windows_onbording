#Requires -RunAsAdministrator
<#
.SYNOPSIS Czyszczenie komputera przed oddaniem nowemu uzytkownikowi
#>

$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

$logPath = "$env:USERPROFILE\Desktop\Cleanup_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)
Start-Transcript -Path $logPath -ErrorAction SilentlyContinue
Write-Host "  Log: $logPath" -ForegroundColor DarkGray

function Write-Step {
    param([string]$Text, [int]$Step, [int]$Total)
    Write-Host ""
    Write-Host "  " + ("-" * 55) -ForegroundColor DarkMagenta
    Write-Host "  KROK $Step/$Total : $Text" -ForegroundColor Magenta
    Write-Host "  " + ("-" * 55) -ForegroundColor DarkMagenta
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

function Pause-AfterError {
    Write-Host "  Nacisnij Enter aby kontynuowac..." -ForegroundColor DarkGray
    $null = Read-Host
}

function Get-FolderSizeMB {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    try {
        $bytes = (Get-ChildItem $Path -Recurse -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        return [math]::Round($bytes / 1MB, 1)
    } catch { return 0 }
}

function Remove-FolderContents {
    param([string]$Path, [string]$Label)
    if (-not (Test-Path $Path)) {
        Write-Host "  [--]   $Label (nie znaleziono)" -ForegroundColor DarkGray
        return 0
    }
    $mb = Get-FolderSizeMB $Path
    try {
        Remove-Item "$Path\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-OK ("$Label (-$mb MB)")
    } catch {
        Write-ERR "$Label : $_"
    }
    return $mb
}

Clear-Host
Write-Host ""
Write-Host "  ╔═════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║   Czyszczenie komputera — przed oddaniem       ║" -ForegroundColor Magenta
Write-Host "  ╚═════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host "  Log: $logPath" -ForegroundColor DarkGray

# ── KROK 0: SYSPREP ───────────────────────────────────────────────────────
Write-Step "Reset do stanu fabrycznego (Sysprep)" 0 5
Write-Host "  UWAGA: Sysprep usunie WSZYSTKIE dane, konta uzytkownikow," -ForegroundColor Red
Write-Host "  aplikacje i ustawienia. System uruchomi sie jak nowy komputer." -ForegroundColor Red
Write-Host ""
if (Ask-YesNo "Wykonac SYSPREP (usunie WSZYSTKO bezpowrotnie)?") {
    Write-Host ""
    Write-Host "  OSTATNIE OSTRZEZENIE: wszystkie dane zostana trwale usuniete." -ForegroundColor Red
    if (Ask-YesNo "  Na pewno kontynuowac sysprep?") {
        $sysprepPath = "C:\Windows\System32\Sysprep\sysprep.exe"
        if (Test-Path $sysprepPath) {
            Write-Host "  Uruchamianie Sysprep... system wylaczy sie automatycznie." -ForegroundColor Red
            Stop-Transcript -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            Start-Process -FilePath $sysprepPath -ArgumentList "/oobe /generalize /shutdown" -Wait
        } else {
            Write-ERR "Nie znaleziono sysprep.exe w $sysprepPath"
            Pause-AfterError
        }
        exit 0
    }
}
Write-Host "  Pominieto Sysprep. Przechodze do recznego czyszczenia." -ForegroundColor DarkGray

# ── KROK 1: PROFILE UZYTKOWNIKOW ─────────────────────────────────────────────
Write-Step "Profile uzytkownikow" 1 5
try {
    $currentUser = $env:USERNAME
    $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
        Where-Object { -not $_.Special -and $_.LocalPath -notmatch "\\$currentUser$" }

    if ($profiles.Count -eq 0) {
        Write-OK "Brak dodatkowych profili."
    } else {
        Write-Host "  Profile (poza aktualnym '$currentUser'):" -ForegroundColor Yellow
        $profiles | ForEach-Object { Write-Host "    • $($_.LocalPath)" -ForegroundColor White }
        Write-Host ""
        if (Ask-YesNo "Usunac wszystkie wymienione profile?") {
            foreach ($p in $profiles) {
                try {
                    Remove-CimInstance -InputObject $p -ErrorAction Stop
                    Write-OK "Usunieto: $($p.LocalPath)"
                } catch {
                    Write-ERR "Blad usuwania $($p.LocalPath): $_"
                }
            }
        } else {
            Write-Host "  Pominieto." -ForegroundColor DarkGray
        }
    }
} catch {
    Write-ERR "Pobieranie profili: $_"
    Pause-AfterError
}

# ── KROK 2: CZYSZCZENIE ──────────────────────────────────────────────────────────
Write-Step "Czyszczenie plikow i cache" 2 5
$totalMB = 0
$totalMB += Remove-FolderContents "C:\Windows\Temp"                                                   "Temp systemowy"
$totalMB += Remove-FolderContents $env:TEMP                                                            "Temp uzytkownika"
$totalMB += Remove-FolderContents "C:\Windows\Prefetch"                                                "Prefetch"
$totalMB += Remove-FolderContents "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"           "Chrome cache"
$totalMB += Remove-FolderContents "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"          "Edge cache"
$totalMB += Remove-FolderContents "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"                        "Firefox cache"

# Kosz
try {
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-OK "Kosz oprózniony"
} catch { Write-WARN "Kosz: $_" }

# Windows Update cache
try {
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    $totalMB += Remove-FolderContents "C:\Windows\SoftwareDistribution\Download" "WU Download cache"
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
} catch { Write-WARN "WU cache: $_" }

# DISM
Write-Host "  Czyszczenie komponentow Windows (DISM, to moze potrwac)..." -ForegroundColor Yellow
try {
    $dismResult = Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1
    Write-OK "DISM zakonczone"
} catch { Write-WARN "DISM: $_" }

Write-Host ""
Write-Host "  Lacznie zwolniono ok. $([math]::Round($totalMB,1)) MB" -ForegroundColor Cyan

# ── KROK 3: APLIKACJE ───────────────────────────────────────────────────────────
Write-Step "Dezinstalacja aplikacji" 3 5
if (Ask-YesNo "Czy chcesz odinstalowac aplikacje?") {
    Write-Host "  Pobieranie listy z rejestru..." -ForegroundColor Yellow
    try {
        $regPaths = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $pkgs = Get-ItemProperty -Path $regPaths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -and $_.UninstallString } |
            Sort-Object DisplayName |
            Group-Object DisplayName | ForEach-Object { $_.Group[0] } |
            Select-Object DisplayName, DisplayVersion, UninstallString

        if ($pkgs.Count -eq 0) {
            Write-Host "  Brak aplikacji w rejestrze." -ForegroundColor DarkGray
        } else {
            Write-Host ""
            for ($i = 0; $i -lt $pkgs.Count; $i++) {
                Write-Host ("  [{0,3}] {1}  v{2}" -f ($i + 1), $pkgs[$i].DisplayName, $pkgs[$i].DisplayVersion) -ForegroundColor White
            }
            Write-Host ""
            Write-Host "  [  0] Odinstaluj WSZYSTKIE" -ForegroundColor Red
            Write-Host ""
            $sel = Read-Host "  Numery oddzielone przecinkami (lub Enter aby pominac)"

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
                    if (-not $app -or -not $app.DisplayName) { continue }
                    Write-Host "  Usuwanie: $($app.DisplayName)..." -ForegroundColor Cyan
                    try {
                        $cmd = $app.UninstallString.Trim()
                        if ($cmd -imatch 'MsiExec') {
                            $code = [regex]::Match($cmd, '\{[A-Za-z0-9-]+\}').Value
                            if ($code) {
                                Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $code /qn /norestart" -Wait -ErrorAction Stop
                            } else {
                                throw "Brak kodu MSI w: $cmd"
                            }
                        } else {
                            Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$cmd`" /S /VERYSILENT /quiet" -Wait -ErrorAction Stop
                        }
                        Write-OK $app.DisplayName
                    } catch {
                        Write-ERR "$($app.DisplayName): $_"
                    }
                }
            }
        }
    } catch {
        Write-ERR "Lista aplikacji: $_"
        Pause-AfterError
    }
} else {
    Write-Host "  Pominieto." -ForegroundColor DarkGray
}

# ── KROK 4: HARMONOGRAM I AUTOSTART ────────────────────────────────────────────
Write-Step "Harmonogram zadan i autostart" 4 5
if (Ask-YesNo "Czy chcesz wyczyścic harmonogram i autostart?") {

    # Harmonogram
    Write-Host "  Niestandardowe zadania harmonogramu:" -ForegroundColor Yellow
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
            Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
            Sort-Object TaskName

        if ($tasks.Count -eq 0) {
            Write-OK "Brak niestandardowych zadan"
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
                        Write-OK "Usunieto: $($tasks[$idx].TaskName)"
                    } catch { Write-ERR "$($tasks[$idx].TaskName): $_" }
                }
            }
        }
    } catch {
        Write-ERR "Harmonogram: $_"
    }

    # Autostart rejestr
    Write-Host ""
    Write-Host "  Wpisy autostartu:" -ForegroundColor Yellow
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    $startupItems = @()
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            try {
                $vals = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                $vals.PSObject.Properties |
                    Where-Object { $_.Name -notmatch '^PS' } |
                    ForEach-Object {
                        $startupItems += [PSCustomObject]@{ Key=$key; Name=$_.Name; Value=$_.Value }
                    }
            } catch { Write-WARN "Odczyt $key : $_" }
        }
    }

    if ($startupItems.Count -eq 0) {
        Write-OK "Brak wpisów autostartu"
    } else {
        for ($i = 0; $i -lt $startupItems.Count; $i++) {
            Write-Host ("  [{0,3}] {1}" -f ($i + 1), $startupItems[$i].Name) -ForegroundColor White
            Write-Host ("       {0}" -f $startupItems[$i].Value) -ForegroundColor DarkGray
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
                    Write-OK "Usunieto: $($startupItems[$idx].Name)"
                } catch { Write-ERR "$($startupItems[$idx].Name): $_" }
            }
        }
    }
} else {
    Write-Host "  Pominieto." -ForegroundColor DarkGray
}

# ── KROK 5: RESET PRZEGLADAREK ───────────────────────────────────────────────
Write-Step "Reset przegladarek do domyslnych" 5 5
if (Ask-YesNo "Czy chcesz zresetowac Chrome i Edge do domyslnych?") {

    # Chrome
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    if (Test-Path $chromePath) {
        try {
            Get-Process -Name "chrome" -ErrorAction SilentlyContinue | Stop-Process -Force
            Start-Sleep -Seconds 2
            Remove-Item $chromePath -Recurse -Force -ErrorAction Stop
            Write-OK "Chrome — profil usuniety"
        } catch { Write-ERR "Chrome: $_" }
    } else {
        Write-Host "  Chrome: profil nie znaleziony." -ForegroundColor DarkGray
    }

    # Edge
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
    if (Test-Path $edgePath) {
        try {
            Get-Process -Name "msedge" -ErrorAction SilentlyContinue | Stop-Process -Force
            Start-Sleep -Seconds 2
            Remove-Item $edgePath -Recurse -Force -ErrorAction Stop
            Write-OK "Edge — profil usuniety"
        } catch { Write-ERR "Edge: $_" }
    } else {
        Write-Host "  Edge: profil nie znaleziony." -ForegroundColor DarkGray
    }

} else {
    Write-Host "  Pominieto." -ForegroundColor DarkGray
}

# ── KONIEC ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔═════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║   Czyszczenie zakonczone. Komputer gotowy.   ║" -ForegroundColor Green
Write-Host "  ╚═════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Stop-Transcript -ErrorAction SilentlyContinue
Write-Host "  Pelny log: $logPath" -ForegroundColor Green
Write-Host ""
if (Ask-YesNo "Zrestartowac teraz?") {
    Write-Host "  Restart za 10 sekund... Ctrl+C aby anulowac." -ForegroundColor Red
    Start-Sleep -Seconds 10
    Restart-Computer -Force
} else {
    Write-Host "  Zalecany restart przed oddaniem komputera." -ForegroundColor Yellow
}
