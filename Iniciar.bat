@echo off
:: Caminho absoluto para o script PS1
set SCRIPT=%~dp0Manutencao.ps1

:: Executa o PowerShell como administrador
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process PowerShell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%SCRIPT%\"' -Verb RunAs"
