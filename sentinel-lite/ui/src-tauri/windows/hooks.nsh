; Vigil installer hooks (Tauri NSIS). Runs elevated (perMachine install).
; Layout after install:
;   $INSTDIR\vigil.exe                  dashboard (tray app)
;   $INSTDIR\sentinel-service.exe       protection engine (Windows service "SentinelLite", LocalSystem)
;   $INSTDIR\signatures\core.json       bundled signature pack
;
; Vigil used to be called Sentinel-Lite and lived in "$PROGRAMFILES64\Sentinel-Lite".
; Installing Vigil (by hand, or as a self-update from a Sentinel-Lite build) moves
; the service over and removes the old copy. Settings, quarantine and logs in
; %ProgramData%\SentinelLite are shared and kept.

!define OLD_DIR "$PROGRAMFILES64\Sentinel-Lite"

!macro NSIS_HOOK_PREINSTALL
  ; Upgrade: stop the running engine so its executable can be replaced.
  IfFileExists "$INSTDIR\sentinel-service.exe" 0 +3
    nsExec::ExecToLog '"$INSTDIR\sentinel-service.exe" stop'
    Sleep 2000 ; let the old process exit and release its files
  ; Migration: the engine may still be running from the old Sentinel-Lite folder.
  IfFileExists "${OLD_DIR}\sentinel-service.exe" 0 +3
    nsExec::ExecToLog '"${OLD_DIR}\sentinel-service.exe" stop'
    Sleep 2000
  ; Close a running dashboard (new and old name).
  nsExec::ExecToLog 'taskkill /IM vigil.exe /F'
  nsExec::ExecToLog 'taskkill /IM sentinel-lite.exe /F'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Install (or reconfigure: points an existing service at this folder) and start it; idempotent.
  nsExec::ExecToLog '"$INSTDIR\sentinel-service.exe" install'
  Pop $0
  StrCmp $0 "0" +2
    ; /SD: silent installs (self-updates run by the SYSTEM service on an invisible
    ; desktop) must never wait for a click that cannot happen.
    MessageBox MB_ICONEXCLAMATION /SD IDOK "The Vigil protection service could not be started (code $0). Protection is NOT active. See %ProgramData%\SentinelLite\logs."
  ; Start the dashboard in the tray at every login.
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Vigil" '"$INSTDIR\vigil.exe" --minimized'
  ; Remove what the old Sentinel-Lite install left behind.
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinel-Lite"
  StrCmp "$INSTDIR" "${OLD_DIR}" done_migration
  IfFileExists "${OLD_DIR}\*.*" 0 done_migration
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Sentinel-Lite"
    DeleteRegKey HKLM "Software\Sentinel-Lite\Sentinel-Lite"
    DeleteRegKey /ifempty HKLM "Software\Sentinel-Lite"
    Delete "$SMPROGRAMS\Sentinel-Lite.lnk"
    Delete "$SMPROGRAMS\Sentinel-Lite\Sentinel-Lite.lnk"
    RMDir "$SMPROGRAMS\Sentinel-Lite"
    Delete "$DESKTOP\Sentinel-Lite.lnk"
    RMDir /r "${OLD_DIR}"
  done_migration:
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::ExecToLog 'schtasks /Delete /F /TN VigilUpdateWatchdog'
  nsExec::ExecToLog 'taskkill /IM vigil.exe /F'
  nsExec::ExecToLog '"$INSTDIR\sentinel-service.exe" uninstall'
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Vigil"
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinel-Lite"
  ; %ProgramData%\SentinelLite (quarantine vault, logs, settings) is kept on purpose
  ; so a reinstall does not lose quarantined items. Delete it manually to purge.
!macroend
