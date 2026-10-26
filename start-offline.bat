@echo off
REM ZENTRA - fully offline launcher (Windows)
cd /d "%~dp0"
set ZENTRA_OFFLINE=true
set GEMINI_API_KEY=

where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is not installed. Install it once from https://nodejs.org ^(LTS^), then run this again.
  pause & exit /b 1
)
if not exist node_modules (
  echo First run only: installing packages ^(needs internet ONE time^)...
  call npm install
  if errorlevel 1 ( echo npm install failed. Connect to internet once and retry. & pause & exit /b 1 )
)
if not exist dist (
  echo Building app...
  call npm run build
  if errorlevel 1 ( pause & exit /b 1 )
)
set NODE_ENV=production
echo.
echo ZENTRA running OFFLINE ^(no cloud AI, no internet needed^)
echo   Laptop : http://localhost:3000
node -e "const n=require('os').networkInterfaces();for(const k in n)for(const i of n[k])if(i.family==='IPv4'&&!i.internal)console.log('  Phone  : http://'+i.address+':3000   (same Wi-Fi / hotspot, no internet needed)')"
echo.
start "" http://localhost:3000
call npx tsx server.ts
pause
