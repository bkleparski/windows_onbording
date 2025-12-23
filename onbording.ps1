function Ensure-Admin {
    param(
        [string]$ScriptUrl = "https://raw.githubusercontent.com/bkleparski/windows_onbording/refs/heads/main/onbording.ps1"
    )

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if (-not $isAdmin) {
        Write-Host "Brak uprawnien administratora. Spróbuje ponownie uruchomic skrypt z podniesionymi uprawnieniami (UAC)..." -ForegroundColor Yellow

        # Jeżeli skrypt jest plikiem na dysku, ponów jego uruchomienie przez -File,
        # w przeciwnym razie (np. iwr | iex) pobierz i wykonaj URL ponownie.
        if ($MyInvocation.MyCommand.Path) {
            $scriptPath = $MyInvocation.MyCommand.Path
            # Zachowaj parametry wywołania, jeśli sa dostępne (np. -NoReboot -NonInteractive)
            $currentArgs = @()
            if ($PSBoundParameters.ContainsKey('NoReboot')) { $currentArgs += "-NoReboot" }
            if ($PSBoundParameters.ContainsKey('NonInteractive')) { $currentArgs += "-NonInteractive" }
            $argString = "-NoProfile -ExecutionPolicy Bypass -File `"" + $scriptPath + "`""
            if ($currentArgs.Count -gt 0) {
                $argString += " " + ($currentArgs -join ' ')
            }
        } else {
            # Użyj URL, aby ponownie pobrać i wykonać skrypt (przydatne przy iwr ... | iex)
            $argString = "-NoProfile -ExecutionPolicy Bypass -Command `"iwr -useb '$ScriptUrl' | iex`""
        }

        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList $argString -Verb RunAs -Wait
        } catch {
            Write-Warning "Nie udalo sie poprosic o podniesienie uprawnien (Start-Process -Verb RunAs nie powiodl sie): $_"
            Write-Warning "Proszę uruchomić PowerShell jako administrator i spróbować ponownie."
        }

        # Zakończ bieżący (niewywyższy) proces — dalsze kroki zrobi podniesione wystąpienie
        Stop-Transcript -ErrorAction SilentlyContinue
        Exit 0
    }
}
