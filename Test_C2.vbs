' [C2 통신 테스트 VBScript]
C2_IP = "10.44.44.44"
C2_PORT = 4444

On Error Resume Next ' 에러 발생 시 중단하지 않음

' TCP 소켓 객체 생성
Set objSocket = CreateObject("MSWinsock.Winsock")

' Kali C2 서버로 연결 시도
objSocket.Connect C2_IP, C2_PORT

' 연결 시도 후 대기
WScript.Sleep 2000 ' 2초 대기

' 연결 상태 확인
If objSocket.State = 7 Then ' 7은 sckConnected 상태를 의미
    MsgBox "C2 통신 연결 성공 (Port 4444가 열려있음)", vbOKOnly, "연결 성공"
Else
    MsgBox "C2 통신 연결 실패 (방화벽 또는 리스너 문제)", vbOKOnly, "연결 실패"
End If

Set objSocket = Nothing