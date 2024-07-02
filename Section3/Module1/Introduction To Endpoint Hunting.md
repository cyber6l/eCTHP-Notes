
When analyzing Windows core processes for legitimacy, it's important to verify several key attributes. These attributes help in determining whether the processes are genuine or potentially malicious imitations. Let's break down each factor and its relevance:
• Name • Purpose • Executable path • Parent process • SID

![image](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/79e05322-b4c0-4ec4-af92-bf156f101ff2)




### Analysis of `smss.exe` (Session Manager Subsystem)

`smss.exe` is a critical Windows core process responsible for managing sessions on a Windows system. Understanding its characteristics is essential for ensuring system integrity and detecting potential security issues

![Screenshot 2024-06-25 133253](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/af68eb69-afdb-4d20-9d9b-c365441b44f5)

#### **Attributes of `smss.exe`**

**Description:**

This process manages the start of user sessions and various other activities including launching Winlogon.exe and Csrss.exe processes, setting system variables, and other activities. If the 2 processes end normally after launch, smss.exe shuts down the system and if they end unexpectedly, smss.exe causes the system to hang.

**Image Path**: 

%SystemRoot%\System32\smss.exe

**Parent Process**: 

System

**Threat hunting tips:**

“smss.exe” that starts with csrss.exe and wininit.exe or with csrss.exe and winlogon.exe, are normal. Additional sessions may be created by RDP and Fast User Switching on shared computers. Remember, only 1 instance of smss.exe must run.


- **Expected Base Priority**: 11
- **Expected Timing**: For Session 0, within seconds of boot time
- Remember only 1 instance of smss.exe should be running

#### Analysis of `csrss.exe` (Client/Server Runtime Subsystem)

`csrss.exe` is an essential Windows core process that plays a crucial role in the management of processes and threads, as well as providing the Windows API to other processes

#### **Attributes of `csrss.exe`**

![Screenshot 2024-06-25 133323](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/3249b060-4c8c-441f-a440-c41fadb7f2b9)

**Description:**

This process is an essential subsystem that must be running at all times. It is responsible for console windows process/thread creation and thread deletion.

**Image Path:** 

%SystemRoot%\System32\csrss.exe

**Parent Process:**  

Created by an instance of smss.exe that exits, so analysis tools usually do not provide the parent process name.

**Threat Hunting Tips**:

Malware authors can disguise their malware to appear as this process by hiding in plain sight. They can change the malware name from ‘csrss.exe’ to something similar but with a misspelling; for instance, cssrss, crss, cssrs, csrsss.


-  **Expected Base Priority**: 13
-  **Expected Timing**: For Sessions 0 & 1, within seconds of boot time.
-  Remember, typically you will see 2 instances of csrss.exe

#### Analysis of `Winlogon.exe` ( Windows Logon Process )
`winlogon.exe` is a crucial system process responsible for handling secure user interactions during the login process. It manages user authentication, loading user profiles, and several other critical tasks. Ensuring the legitimacy of `winlogon.exe` is vital for system security

![Screenshot 2024-06-25 142933](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/a145049f-d405-4389-ae3d-3b2c59a7aa8c)

#### **Attributes of `Winlogon.exe`

Winlogon handles interactive user logons and logoffs.  It launches LogonUI.exe, which accepts the username and password at the logon screen and passes the credentials to lsass.exe to validate the credentials.  Once the user is authenticated, Winlogon loads the user’s NTUSER.DAT into HKEY_CURRENT_USER Registry Hive and starts the user’s shell (explorer.exe) via Userinit.exe.

**Image Path:** 

%SystemRoot%\System32\winlogon.exe

**Parent Process:** 

Created by an instance of smss.exe that exits, so analysis tools usually do not provide the parent process name.

**Threat Hunting Tips**:

The abuse within this process often comes within the different components of the login process. Malware sometimes mishandles the SHELL registry value. This value should be explorer.exe


- **Expected Base Priority**: 13
- **Expected Timing**: During the early stages of the boot process


### Analysis of `wininit.exe` (Windows Initialization Process)
`wininit.exe` is a core Windows system process responsible for initializing the user-mode side of the Win32 subsystem. This includes starting services and initializing system drivers. Ensuring the legitimacy of `wininit.exe` is essential for maintaining system integrity

![Screenshot 2024-06-25 142617](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/149ae02c-9f3f-49ba-82af-0098542ec797)

#### **Attributes of `wininit.exe`**

**Description:**

This process is an essential part of the Windows OS and it runs in the background. “wininit.exe” is responsible for launching the Windows Initialization process. Wininit starts key background processes within Session 0.  It starts with the Service Control Manager (services.exe), the Local Security Authority process (lsass.exe), and the Local Session Manager (lsm.exe).

**Image Path:**  

%SystemRoot%\System32\wininit.exe

**Parent Process:** 

Created by an instance of smss.exe that exits, so tools usually do not provide the parent process name.

**Number of Instances:** 

One

**User Account:** 

Local System

**Threat hunting tips:**

There must be only one instance of wininit.exe. You should check the parent process to see if it is spawning wininit.exe. You should also check whether this process is located somewhere other than its usual path. You should also check the spelling



### Analysis of `lsm.exe` (Local Session Manager)



#### **Attributes of `lsm.exe`**

**Description:**

`lsm.exe` is a critical system process that runs in the background on Windows OS. It is responsible for managing user sessions and is especially important in multi-user environments such as Terminal Services. It helps in managing and maintaining sessions on the system

**Image Path:**

%SystemRoot%\System32\lsm.exe

**Parent Process:**

Created by `wininit.exe`.

**Number of Instances:**

One

**User Account:**

Local System 

**Threat hunting tips:**

Ensure only one instance of `lsm.exe` is running. Verify `lsm.exe` is started by `wininit.exe`. Confirm `lsm.exe` runs from `%SystemRoot%\System32\lsm.exe`. Watch for misspelled variants or suspiciously similar processes.

### Analysis of `lsass.exe` (Local Security Authority Subsystem Service)

![Screenshot 2024-06-25 165459](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/b683f7a1-c7a2-44fc-b182-bc92f847aafd)

#### **Attributes of `lsass.exe`**

**Description:**

`lsass.exe` is a critical system process responsible for enforcing security policies, handling user logins, password changes, and creating access tokens. It also manages the Local Security Authority (LSA) process, which is crucial for authenticating users and ensuring system security.

**Image Path:**

%SystemRoot%\System32\lsass.exe

**Parent Process:**

Created by `wininit.exe`.

**Number of Instances:**

One

**User Account:**

Local System 

**Threat hunting tips:**

Ensure only one instance of `lsass.exe` is running. Validate `lsass.exe` is spawned by `wininit.exe`. Confirm `lsass.exe` runs from `%SystemRoot%\System32\lsass.exe`. Watch out for misspelled variants



#### lsm.exe vs lsass.exe 

### Key Differences:

- **Function:** `lsm.exe` manages user sessions, while `lsass.exe` focuses on security enforcement and authentication.
- **Responsibilities:** `lsm.exe` ensures smooth session transitions and management, whereas `lsass.exe` handles authentication processes and security policy enforcement.
- **Criticality:** Both are critical system processes, but `lsass.exe` directly impacts system security and user authentication, making it more security-sensitive.
- **Execution:** `lsm.exe` is crucial for session initialization and management from the early stages of system boot, whereas `lsass.exe` plays a continuous role in user authentication and security operations throughout system uptime



## **Services.exe**

![Screenshot 2024-06-25 170016](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/c1062bac-b25d-4d1b-a45c-e0a1e155aa69)

**Description:**

services.exe launches the Services Control Manager which is primarily responsible for handling system services including starting and ending services, and interacting with services. Services are defined in HKLM\SYSTEM\CurrentControlSet\Services. “services.exe” is the parent process of svchost.exe, dllhost.exe, taskhost.exe,spoolsv.exe, etc.

**Image Path:** 

%SystemRoot%\System32\services.exe

**Parent Process:**  

wininit.exe

**Number of Instances:** 

One

**User Account:** 

Local System

**Threat hunting tips:**

There must only be 1 instance of “services.exe”. This is a protected process that makes it difficult to tamper with. Also track Event ID Event ID 4697 ( security ) & Event ID 7045 (system )



## **Svchost.exe(service host)**

**Description:** 

The generic host process for Windows Services. It is used for running service DLLs. Windows will run multiple instances of svchost.exe, each using a unique “-k” parameter for grouping similar services. Typical “-k” parameters include BTsvcs, DcomLaunch, RPCSS, LocalServiceNetworkRestricted, netsvcs, LocalService, NetworkService, LocalServiceNoNetwork, secsvcs, and LocalServiceAndNoImpersonation.

![Screenshot 2024-06-25 170153](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/147bd536-817d-4df9-9410-7899abbaf3b5)
**BTsvcs, DcomLaunch, RPCSS, LocalServiceNetworkRestricted, netsvcs, LocalService, NetworkService, LocalServiceNoNetwork, secsvcs, and LocalServiceAndNoImpersonation.**

![Screenshot 2024-06-25 170231](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/bf732bb2-9d2a-40c8-aa2a-3ab1afcf2846)

**Image Path:** 

%SystemRoot%\System32\svchost.exe

**Parent Process:** 

services.exe

**Number of Instances:** 

Five or more

**User Account:** 

Varies depending on svchost instance, though it typically will be Local System, Network Service, or Local Service accounts. Instances running under any other account should be investigated.

**Legitimate svchost runs on**

%SystemRoot%\System32\svchost.exe and it should be the children of services.exe

**Threat Hunting Tips:**

This process can be used to launch malicious services (malware installed as a service). Once the malicious service is launched, **“-k”** will not be present. This process hides in plain sight through misspellings of words. Another method to utilize this process for malicious purposes is to place it in different directories and paths; However, note in such a case, services.exe would not be the parent process.






### Analysis of `taskhost.exe`

![Screenshot 2024-06-25 170755](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/74141e2c-73fe-43b9-9f53-e12d82ced3ab)

**Description:**

`taskhost.exe` is a legitimate Windows process responsible for launching tasks based on triggers such as user actions or system events. It helps manage background processes and services efficiently.

**Executable Path:**

%SystemRoot%\System32\taskhost.exe

**Parent Process:**

Typically spawned by `svchost.exe` or `explorer.exe`, depending on the context of the task.

**Number of Instances:**

Multiple instances can run simultaneously depending on the tasks triggered.

**User Account:**

Varies based on the context in which it is executed, often under the context of the logged-in user or as a system service.

### Analysis of `explorer.exe`

![Screenshot 2024-06-25 171038](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/636c315d-172c-45e0-abd4-7aeabf1ae9ed)

**Description:**

`explorer.exe` is a fundamental Windows process responsible for managing the graphical user interface (GUI) and providing the desktop environment. It allows users to interact with files, folders, and applications through the Windows Explorer interface.

**Executable Path:**

%SystemRoot%\explorer.exe (typically `C:\Windows\explorer.exe`)

**Parent Process:**

Usually initiated by the Windows Shell (`explorer.exe`) itself upon user login.

**Number of Instances:**

Typically, only one instance per user session, but multiple instances can occur in specific scenarios.

**User Account:**

Runs under the context of the logged-in user.

---

#### Endpoint Baselines

To create and use baselines for monitoring running services and processes on a Windows machine, you can use PowerShell. Here's a summary of how to establish and utilize these baselines:

### **Creating a Services Baseline**

1. **Get a list of running services:**
    
    `Get-Service * | Where-Object {$_.Status -eq "Running"} | Export-Clixml -Path "Baseline-Services.xml"`
    
    - `Get-Service *` retrieves all services.
    - `Where {$_.Status -eq "Running"}` filters to show only running services.
    - The information is exported to an XML file named `Baseline-Services.xml`.
2. **Compare the current services to the baseline:**
    
		Compare-Object (Import-Clixml Baseline-Services.xml) (Get-Service | Where {$_.status -eq "Running"}) -Property DisplayName | Where-Object {$_.sideindicator -eq "<="}
		
- `Import-Clixml Baseline-Services.xml`: This command imports the baseline list of services from an XML file.
- `Get-Service | Where {$_.status -eq "Running"}`: This retrieves the current list of running services.
- `Compare-Object`: This cmdlet compares the two sets of objects (baseline services and current services).
- `-Property DisplayName`: This parameter specifies that the comparison should be based on the `DisplayName` property of the services.
- `Where-Object {$_.sideindicator -eq "<="}`: This filters the comparison results to show only the services that are different from the baseline.

### **Creating a Processes Baseline**

1. **Get a list of running processes:**
    
    
    `Get-Process | Export-Clixml -Path "Baseline-Processes.xml"`
    
    - `Get-Process` retrieves all processes.
    - The information is exported to an XML file named `Baseline-Processes.xml`.
2. **Compare the current processes to the baseline:**
    
    
    `Compare-Object (Import-Clixml Baseline-Processes.xml) (Get-Process) -Property Name | Where-Object {$_.sideindicator -eq "<="}`
    
    ### Explanation

- `Import-Clixml Baseline-Services.xml`: This command imports the baseline list of services from an XML file.
- `Get-Service | Where {$_.status -eq "Running"}`: This retrieves the current list of running services.
- `Compare-Object`: This cmdlet compares the two sets of objects (baseline services and current services).
- `-Property DisplayName`: This parameter specifies that the comparison should be based on the `DisplayName` property of the services.
- `Where-Object {$_.sideindicator -eq "<="}`: This filters the comparison results to show only the services that are different from the baseline.

### **Additional Baselines to Consider**

- **Accounts on a system (user or service)**
- **Local administrators on a system**
- **Folder permissions**
- **Folder contents**
- **Tasks folder (scheduled tasks)**
- **Network folders containing internal installation executables & files**

---
