@echo off
setlocal EnableDelayedExpansion
rem Refuse to modify UAC outside the single-disk QEMU validation guest.
wmic computersystem get manufacturer 2>nul | findstr /i /c:"QEMU" >nul || exit /b 1
curl.exe --fail --silent --retry 10 --retry-delay 2 --max-time 20 -X POST --data-binary setup-start http://10.233.42.1:18765/v1/event >nul 2>&1 || goto refused
wmic diskdrive get model 2>nul | findstr /i /c:"QEMU" >nul || goto refused
for /l %%I in (1,1,30) do (
  for /f %%N in ('wmic diskdrive get model /value ^| findstr /i /b "Model=" ^| find /c /v ""') do set DISKLINES=%%N
  if "!DISKLINES!"=="1" goto diskready
  timeout.exe /t 1 /nobreak >nul
)
goto refused
:diskready
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f >nul || goto refused
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f >nul || goto refused
rem Reboot directly so UAC is active before the optical-media test agent runs.
curl.exe --silent --max-time 3 -X POST --data-binary setup-reboot http://10.233.42.1:18765/v1/event >nul 2>&1
shutdown.exe /r /t 45 /c NetFlowValidationSetup >nul
exit /b 0
:refused
curl.exe --silent --max-time 3 -X POST --data-binary setup-refused http://10.233.42.1:18765/v1/event >nul 2>&1
exit /b 1
