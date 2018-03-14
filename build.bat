@echo off
cls

@rem paket.exe install
paket.exe install
if errorlevel 1 (
  exit /b %errorlevel%
)

"Src\packages\FAKE\tools\Fake.exe" Src\build.fsx %*
