; Sentinel-Lite installer hooks (Tauri NSIS). Runs elevated (perMachine install).
; Layout after install:
;   $INSTDIR\sentinel-lite.exe          dashboard (tray app)
;   $INSTDIR\sentinel-service.exe       protection engine (Windows service, LocalSystem)
;   $INSTDIR\signatures\core.json       bundled signature pack

!macro NSIS_HOOK_PREINSTALL
  ; Upgrade: stop the running engine so its executable can be replaced.
  IfFileExists "$INSTDIR\sentinel-service.exe" 0 +2
    nsExec::ExecToLog '"$INSTDIR\sentinel-service.exe" stop'
  ; Close a running dashboard instance.
  nsExec::ExecToLog 'taskkill /IM sentinel-lite.exe /F'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Install (or reconfigure) and start the service; idempotent.
  nsExec::ExecToLog '"$INSTDIR\sentinel-service.exe" install'
  Pop $0
  StrCmp $0 "0" +2
    MessageBox MB_ICONEXCLAMATION "The Sentinel-Lite protection service could not be started (code $0). Protection is NOT active. See %ProgramData%\SentinelLite\logs."
  ; Start the dashboard in the tray at every login.
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinel-Lite" '"$INSTDIR\sentinel-lite.exe" --minimized'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog 'taskkill /IM sentinel-lite.exe /F'
  nsExec::ExecToLog '"$INSTDIR\sentinel-service.exe" uninstall'
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinel-Lite"
  ; %ProgramData%\SentinelLite (quarantine vault, logs, settings) is kept on purpose
  ; so a reinstall does not lose quarantined items. Delete it manually to purge.
!macroend
