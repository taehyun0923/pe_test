@echo off
chcp 65001 >nul
color 0A
title 악성코드 레지스트리 복구 도구

echo ============================================================
echo 악성코드 레지스트리 복구 시작
echo ============================================================
echo.

REM 관리자 권한 확인
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [오류] 관리자 권한이 필요합니다!
    echo 이 파일을 우클릭 후 "관리자 권한으로 실행"하세요.
    echo.
    pause
    exit /b 1
)

echo [1/6] 시작프로그램 악성 항목 제거 중...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsServiceHost" /f >nul 2>&1
if %errorLevel% equ 0 (
    echo   ✓ 시작프로그램 악성 항목 제거 완료
) else (
    echo   - 시작프로그램 악성 항목 없음
)

echo [2/6] Windows Defender 활성화 중...
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /f >nul 2>&1
sc config WinDefend start=auto >nul 2>&1
sc start WinDefend >nul 2>&1
echo   ✓ Windows Defender 활성화 완료

echo [3/6] UAC(사용자 계정 컨트롤) 활성화 중...
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 5 /f >nul 2>&1
echo   ✓ UAC 활성화 완료

echo [4/6] Windows Update 활성화 중...
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /f >nul 2>&1
sc config wuauserv start=demand >nul 2>&1
sc start wuauserv >nul 2>&1
echo   ✓ Windows Update 활성화 완료

echo [5/6] Windows 방화벽 활성화 중...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "EnableFirewall" /t REG_DWORD /d 1 /f >nul 2>&1
netsh advfirewall set allprofiles state on >nul 2>&1
echo   ✓ Windows 방화벽 활성화 완료

echo [6/6] 숨김 파일 표시 설정 복구 중...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f >nul 2>&1
echo   ✓ 숨김 파일 표시 설정 복구 완료

echo.
echo ============================================================
echo 악성 파일 검색 중...
echo ============================================================
echo.

set "found=0"
set "logpath=%APPDATA%\Microsoft\Windows Defender\Logs"
if exist "%logpath%\System_Report_*" (
    echo 발견된 의심 파일:
    dir /b "%logpath%\System_Report_*" 2>nul
    set "found=1"
)

set "logpath2=C:\ProgramData\Logs\SystemCache"
if exist "%logpath2%\System_Report_*" (
    echo 발견된 의심 파일:
    dir /b "%logpath2%\System_Report_*" 2>nul
    set "found=1"
)

if %found%==1 (
    echo.
    set /p choice="이 파일들을 삭제하시겠습니까? (Y/N): "
    if /i "%choice%"=="Y" (
        del /f /q "%APPDATA%\Microsoft\Windows Defender\Logs\System_Report_*" 2>nul
        del /f /q "C:\ProgramData\Logs\SystemCache\System_Report_*" 2>nul
        echo   ✓ 악성 파일 삭제 완료
    )
) else (
    echo   의심 파일이 발견되지 않았습니다.
)

echo.
echo ============================================================
echo 복구 완료!
echo ============================================================
echo.
echo 모든 레지스트리가 복구되었습니다.
echo.
echo 추가 권장 조치:
echo   1. Windows Defender 전체 검사 실행
echo   2. 모든 계정 비밀번호 변경
echo   3. 시스템 재시작
echo.
echo ============================================================
pause