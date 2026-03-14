# windows_onbording

Skrypt PowerShell do automatycznego przygotowania nowego komputera z systemem Windows. Wykonuje pełny onboarding stacji roboczej: aktualizacje, instalację aplikacji, konfigurację i opcjonalny restart.

## Co robi skrypt?

1. **Logowanie** — zapisuje przebieg do pliku logu w `%TEMP%`
2. **Windows Update** — instaluje wszystkie dostępne aktualizacje (przez moduł `PSWindowsUpdate`)
3. **Instalacja aplikacji** przez `winget`:
   - 7-Zip
   - Adobe Acrobat Reader (64-bit)
   - Google Chrome
   - Oracle Java Runtime Environment
   - TightVNC
   - Fortinet FortiClient VPN
4. **Uruchomienie winutil** — otwiera narzędzie `winutil.ps1` w osobnym oknie (skrypt Ravnet do zaawansowanej konfiguracji Windows)
5. **Zarządzanie aplikacjami** — interaktywna lista zainstalowanych aplikacji z możliwością usuwania wybranych pozycji
6. **Restart systemu** — opcjonalny restart po zakończeniu konfiguracji

## Wymagania

- Windows 10 / Windows 11
- PowerShell uruchomiony jako **Administrator**
- `winget` (App Installer)
- Połączenie z Internetem

## Użycie

```powershell
# Uruchomienie interaktywne (zalecane)
.\onbording.ps1

# Bez restartu na końcu
.\onbording.ps1 -NoReboot

# Tryb nieinteraktywny (np. w skryptach automatyzacji)
.\onbording.ps1 -NonInteractive
```

### Parametry

| Parametr          | Opis                                                          |
|-------------------|---------------------------------------------------------------|
| `-NoReboot`       | Pomija restart komputera na końcu skryptu                     |
| `-NonInteractive` | Wyłącza interaktywne menu — restart wykonywany automatycznie po 10 s |

> **Uwaga:** Skrypt wymaga uruchomienia PowerShell jako **Administrator**. Jeśli zostanie uruchomiony bez uprawnień, zakończy działanie z ostrzeżeniem.
