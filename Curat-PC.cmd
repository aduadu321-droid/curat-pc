@echo off
rem Curat-PC launcher - double-click to run the health check
rem The PowerShell script self-elevates (asks for Administrator).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Curat-PC.ps1" %*
