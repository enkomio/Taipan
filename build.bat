@echo off
cls

@rem Move to src directory
cd Src

@rem paket.exe install
paket.exe install
if errorlevel 1 (
  exit /b %errorlevel%
)

"packages\FAKE\tools\Fake.exe" build.fsx %*

cd ..