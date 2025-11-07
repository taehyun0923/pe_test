' C2 Communication Test Script (English)
' This script attempts to establish an Outbound TCP connection to the Kali C2 server.

C2_IP = "10.44.44.44"  ' <<< REPLACE with your Kali Linux IP
C2_PORT = 4444        ' <<< C2 Listener Port

' Error Handling: Prevents the script from crashing if connection fails
On Error Resume Next 

' Create a Winsock object for TCP connection
Set objSocket = CreateObject("MSWinsock.Winsock")

' Attempt to connect to the C2 server IP and Port
objSocket.Connect C2_IP, C2_PORT

' Wait for 2 seconds to allow connection attempt to complete
WScript.Sleep 2000

' Check the connection state
' State 7 (sckConnected) means connection was successful
If objSocket.State = 7 Then 
    ' Connection Succeeded
    MsgBox "C2 Communication Successful (Port " & C2_PORT & " is Open)", vbOKOnly, "Connection Success"
Else
    ' Connection Failed
    MsgBox "C2 Communication Failed (Firewall or Listener Issue)", vbOKOnly, "Connection Failure"
End If

' Clean up the object
Set objSocket = Nothing