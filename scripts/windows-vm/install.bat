@echo off
setlocal
rem Refuse to modify UAC outside the single-disk QEMU validation guest.
wmic computersystem get manufacturer 2>nul | findstr /i /c:"QEMU" >nul || exit /b 1
wmic diskdrive get model 2>nul | findstr /i /c:"QEMU" >nul || exit /b 1
for /f %%N in ('wmic diskdrive get model /value ^| findstr /i /b "Model=" ^| find /c /v ""') do set DISKLINES=%%N
if not "%DISKLINES%"=="1" exit /b 1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f >nul
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f >nul
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v NetFlowVMVerify /t REG_SZ /d "C:\OEM\netflow-vm-agent.exe" /f >nul
rem FirstLogonCommands may run after RunOnce was already processed. Reboot
rem directly so UAC is active before the persistent guest agent is started.
shutdown.exe /r /t 45 /c NetFlowValidationSetup >nul
exit /b 0
