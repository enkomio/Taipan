@echo off
cls

@rem paket.exe install
paket.exe install
if errorlevel 1 (
  exit /b %errorlevel%
)

"packages\FAKE\tools\Fake.exe" build.fsx %*