@echo off
setlocal

set "chrome="
if exist "%PROGRAMFILES%\Google\Chrome\Application\chrome.exe" set "chrome=%PROGRAMFILES%\Google\Chrome\Application\chrome.exe"
if exist "%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe" set "chrome=%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe"
if exist "%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe" set "chrome=%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"

if defined chrome (
    start "" "%chrome%" --app="file:///%~dp0openauth.html"
) else (
    echo Chrome not found — opening in default browser.
    start "" "%~dp0openauth.html"
)
