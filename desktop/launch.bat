@echo off
setlocal
set "PATH=%~dp0;%PATH%"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -c "import tkinter" >nul 2>nul
  if errorlevel 1 (
    echo ARAP desktop needs Python 3 with Tk 8.6. Modify Python installation and enable Tcl/Tk support.
    exit /b 1
  )
  py -3 "%~dp0arap_desktop.py" %*
) else (
  python -c "import tkinter" >nul 2>nul
  if errorlevel 1 (
    echo ARAP desktop needs Python 3 with Tk 8.6. Install Python with Tcl/Tk support.
    exit /b 1
  )
  python "%~dp0arap_desktop.py" %*
)
exit /b %errorlevel%
