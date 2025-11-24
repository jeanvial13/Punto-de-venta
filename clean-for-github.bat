@echo off
REM VICMAN - Limpiar proyecto antes de subir a GitHub
REM Este script elimina todos los archivos pesados que Docker reinstalará

echo ========================================
echo VICMAN - Limpieza para GitHub
echo ========================================
echo.

echo [1/4] Limpiando node_modules del backend...
if exist "backend\node_modules" (
    rmdir /s /q "backend\node_modules"
    echo   - Backend node_modules eliminado
) else (
    echo   - Backend node_modules ya no existe
)

echo.
echo [2/4] Limpiando node_modules del frontend...
if exist "frontend\node_modules" (
    rmdir /s /q "frontend\node_modules"
    echo   - Frontend node_modules eliminado
) else (
    echo   - Frontend node_modules ya no existe
)

echo.
echo [3/4] Limpiando archivos de build...
if exist "backend\dist" rmdir /s /q "backend\dist"
if exist "frontend\dist" rmdir /s /q "frontend\dist"
if exist "frontend\build" rmdir /s /q "frontend\build"
echo   - Archivos de build eliminados

echo.
echo [4/4] Limpiando package-lock.json...
if exist "backend\package-lock.json" del /q "backend\package-lock.json"
if exist "frontend\package-lock.json" del /q "frontend\package-lock.json"
echo   - Lock files eliminados

echo.
echo ========================================
echo LIMPIEZA COMPLETADA
echo ========================================
echo.
echo La carpeta ahora debe pesar menos de 10 MB
echo.
echo Proximos pasos:
echo 1. git add .
echo 2. git commit -m "Initial commit - VICMAN"
echo 3. git push
echo.
pause
