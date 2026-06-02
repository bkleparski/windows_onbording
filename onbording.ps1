#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Ravnet Windows Tools - Launcher
    irm go.ebartnet.pl/onbording | iex
#>

$ErrorActionPreference = "Continue"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force -ErrorAction SilentlyContinue

$logPath = "$env:USERPROFILE\Desktop\RavnetTools_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date)
Start-Transcript -Path $logPath -ErrorAction SilentlyContinue
Write-Host "  Log sesji: $logPath" -ForegroundColor DarkGray

$BASE = "https://raw.githubusercontent.com/bkleparski/windows_onbording/main"

function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "  ============================================" -ForegroundColor Cyan
    Write-Host "      Ravnet Windows Tools -- Launcher        " -ForegroundColor Cyan
    Write-Host "      github.com/bkleparski/windows_onbording " -ForegroundColor DarkGray
    Write-Host "  ============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Log: $logPath" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  [1]  Nowy komputer    -- pelny onboarding" -ForegroundColor Yellow
    Write-Host "  [2]  Czyszczenie      -- przygotowanie do oddania" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  [0]  Wyjdz" -ForegroundColor DarkGray
    Write-Host ""
}

function Invoke-RemoteScript {
    param([string]$Url, [string]$Name)
    Write-Host "  Pobieranie: $Url" -ForegroundColor DarkGray
    try {
        # Pobierz jako tekst (PS dekoduje UTF-8 automatycznie)
        $content = Invoke-RestMethod -Uri $Url -ErrorAction Stop

        # Zapisz z BOM zeby PS 5.1 poprawnie interpretowal UTF-8
        $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.ps1'
        $bom = [byte[]](0xEF, 0xBB, 0xBF)
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
        [System.IO.File]::WriteAllBytes($tmp, $bom + $bytes)

        Write-Host "  Uruchamianie: $Name" -ForegroundColor Cyan
        Write-Host ""
        & $tmp
    } catch {
        Write-Host ""
        Write-Host "  BLAD: $_" -ForegroundColor Red
        Write-Host "  Sprawdz polaczenie z internetem." -ForegroundColor Yellow
    } finally {
        if (Test-Path $tmp) { Remove-Item $tmp -ErrorAction SilentlyContinue }
    }
    Write-Host ""
    Write-Host "  Skrypt zakonczony. Nacisnij Enter aby wrocic do menu..."
    $null = Read-Host
}

$running = $true
while ($running) {
    Show-Menu
    $choice = Read-Host "  Wybor"
    switch ($choice) {
        "1" { Invoke-RemoteScript -Url "$BASE/new-pc.ps1"  -Name "Nowy komputer" }
        "2" { Invoke-RemoteScript -Url "$BASE/cleanup.ps1" -Name "Czyszczenie" }
        "0" {
            Write-Host "`n  Do zobaczenia!" -ForegroundColor Green
            Stop-Transcript -ErrorAction SilentlyContinue
            Write-Host "  Pelny log: $logPath" -ForegroundColor DarkGray
            $running = $false
        }
        default { Write-Host "`n  Nieznana opcja." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}
