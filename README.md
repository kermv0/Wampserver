### MSf Wampserver Dll Hijacking Exploit - PrivEsc & Persistence

![image](https://user-images.githubusercontent.com/19262430/37789415-7df443a8-2e0c-11e8-8456-160bda417b77.png)

 Wampserver contain DLL hijacking vulnerability, that could allow an unauthenticated, remote attacker to execute arbitrary code on the targeted system and elevated in "HighestAvailable". 

![image](https://user-images.githubusercontent.com/19262430/37790752-145e8684-2e10-11e8-80d9-23e6c1797bdf.png)

This vulnerability exists due to DLL files - olepro32.dll and RICHED20.dll - is loaded by wampmanager.exe improperly. By default Wampserver installation folder is c:\wamp64 so it allows an attacker to add malicious DLLs in this folder.


#### OPTIONS
###### DLLNAME
Upload malicious dll with name olepro32 or RICHED20
###### MODE
ON execute wampmanager, OFF not execute wampmanager
###### PATH
Malicious dll path
###### SESSION
Meterpreter Session

![image](https://user-images.githubusercontent.com/19262430/37789722-538fa32c-2e0d-11e8-8ebb-7ea34519e430.png)
