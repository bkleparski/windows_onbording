#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Ravnet Windows Tools — Launcher
    irm go.ebartnet.pl/onbording | iex
#>

$BASE = "https://raw.githubusercontent.com/bkleparski/windows_onbording/main"

function Show-Menu {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔═════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║      Ravnet Windows Tools — Launcher      ║" -ForegroundColor Cyan
    Write-Host "  ║  github.com/bkleparski/windows_onbording  ║" -ForegroundColor DarkGray
    Write-Host "  ╚═════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1]  Nowy komputer    — pelny onboarding" -ForegroundColor Yellow
    Write-Host "  [2]  Czyszczenie      — przygotowanie do oddania" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  [0]  Wyjdz" -ForegroundColor DarkGray
    Write-Host ""
}

function Invoke-RemoteScript {
    param([string]$Url)
    Write-Host "  Pobieranie skryptu..." -ForegroundColor DarkGray
    $tmp = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.ps1'
    try {
        Invoke-RestMethod -Uri $Url -OutFile $tmp
        & $tmp
    } finally {
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }
}

$running = $true
while ($running) {
    Show-Menu
    $choice = Read-Host "  Wybor"
    switch ($choice) {
        "1" { Write-Host ""; Invoke-RemoteScript -Url "$BASE/new-pc.ps1" }
        "2" { Write-Host ""; Invoke-RemoteScript -Url "$BASE/cleanup.ps1" }
        "0" { Write-Host "`n  Do zobaczenia!" -ForegroundColor Green; $running = $false }
        default { Write-Host "`n  Nieznana opcja." -ForegroundColor Red; Start-Sleep -Seconds 1 }
    }
}
