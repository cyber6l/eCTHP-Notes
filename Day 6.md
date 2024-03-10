# << 1.2 Windows Processes >>

 عندنا عوامل رئيسيه
   to detect if they are the legitimate core processes : 
• Is it running out of the expected path?
• Is it spelled correctly?
• Is it running under the proper SID? ,etc..

such as this snapshot of processes running on a Windows system (VM)
![[Screenshot 2024-03-10 184815 1.png]]
• Name • Purpose • Executable path • Parent process • SID

#### What is smss.exe ?
<mark style="background: #ADCCFFA6;"> (Session Manager Subsystem)</mark>

	 Its responsibility is to create new sessions.
• Session 0 starts csrss.exe and wininit.exe. (OS services) 
• Session 1 starts csrss.exe and winlogon.exe. (User session)

- **Executable Path:** `%SystemRoot%\System32\smss.exe` (likely `C:\Windows\System32\smss.exe`)
- **Parent Process:** System
- **Username:** `NT AUTHORITY\SYSTEM (S-1-5-18)`
- **Base Priority:** `11` (indicating a moderate priority level)
- **Time of Execution:** Within seconds of boot time, specifically for Session 0

<mark style="background: #D2B3FFA6;">*Remember only 1 instance of smss.exe should be running.*</mark>

#### What is csrss.exe ?
<mark style="background: #ADCCFFA6;">(Client/Server Run Subsystem Process)</mark>

	is a critical system process in Windows that performs various essential functions for the operating syste . is responsible for creating and deleting user sessions, which are separate environments for running applications and managing user interactions

**Session Initialization:** (Session 0) It initializes the system session 
				   (Session 1 and above) during the boot process

![[Pasted image 20240310185754.png]]

- **Executable Path:** `%SystemRoot%\System32\csrss.exe` (likely `C:\Windows\System32\csrss.exe`)
- **Parent Process:** Created by a child instance of `smss.exe`, but the parent process won't exist during observation
- **Username:** `NT AUTHORITY\SYSTEM (S-1-5-18)`
- **Base Priority:** `13` (indicating a relatively high priority level)
- **Time of Execution:** Within seconds of boot time, specifically for Sessions 0 & 1

<mark style="background: #D2B3FFA6;">*Remember, typically you will see 2 instances of csrss.exe.*</mark>

#### What is WINLOGON.EXE ?
<mark style="background: #ADCCFFA6;">(Windows Logon Process Executable)</mark>

	manages user logons and logoffs in Windows. It launches the logon interface, verifies credentials, loads user profiles, and initializes the user environment, including running logon scripts and Group Policy Objects

- **Executable Path:** `%SystemRoot%\System32\winlogon.exe` (likely `C:\Windows\System32\winlogon.exe`)
- **Parent Process:** Created by a child instance of `smss.exe`, but the parent process won't exist during observation
- **Username:** `NT AUTHORITY\SYSTEM (S-1-5-18)`
- **Base Priority:** `13` (indicating a relatively high priority level)
- **Time of Execution:** Within seconds of boot time for Session 1; additional instances may start later

#### What is WININIT.EXE ?
<mark style="background: #ADCCFFA6;">(Windows Initialization Process)</mark>

	responsible for launching essential system processes like `services.exe`, `lsass.exe`, and `lsm.exe` during the boot process in Session 0
	
- **Executable Path:** `%SystemRoot%\System32\wininit.exe` (likely `C:\Windows\System32\wininit.exe`)
- **Parent Process:** Created by a child instance of `smss.exe`, but the parent process won't exist during observation
- **Username:** `NT AUTHORITY\SYSTEM (S-1-5-18)`
- **Base Priority:** `13` (indicating a relatively high priority level)
- **Time of Execution:** Within seconds of boot time
![[Screenshot 2024-03-10 192326 1.png]]

- **Executable Path:** `%SystemRoot%\System32\lsm.exe` (likely `C:\Windows\System32\lsm.exe`)
- **Parent Process:** `wininit.exe`
- **Username:** `NT AUTHORITY\SYSTEM (S-1-5-18)`
- **Base Priority:** `8` (indicating a relatively low base priority)
- **Time of Execution:** Within seconds of boot time


#### What is services.exe ?
<mark style="background: #ADCCFFA6;">Service Control Manager</mark>

	responsible for loading auto-start services and device drivers into memory
	- Database Maintenance: Maintains an in-memory database of service information that can be queried using the built-in Windows tool, `sc.exe`
    
- **Registry Backup:** After a successful interactive login, `services.exe` backs up registry keys to `HKLM\SYSTEM\Select\LastKnownGood`
- **Executable Path:** `%SystemRoot%\System32\services.exe` (likely `C:\Windows\System32\services.exe`)
- **Parent Process:** `wininit.exe`
- **Username:** `NT AUTHORITY\SYSTEM (S-1-5-18)`
- **Base Priority:** `9` (indicating a relatively low base priority)
- **Time of Execution:** Within seconds of boot time

#### What is lsass.exe ?
<mark style="background: #ADCCFFA6;">Local Security Authority Subsystem</mark>

	 responsible for user authentication and generating access tokens with security policies for user sessions , Authentication Packages: Uses authentication packages defined in `HKLM\System\CurrentControlSet\Control\Lsa` to authenticate users

- **Executable Path:** `%SystemRoot%\System32\lsass.exe` (likely `C:\Windows\System32\lsass.exe`)
- **Parent Process:** `wininit.exe`
- **Username:** `NT AUTHORITY\SYSTEM (S-1-5-18)`
- **Base Priority:** `9` (indicating a relatively low base priority)
- **Time of Execution:** Within seconds of boot

#### What is svchost.exe ?
<mark style="background: #ADCCFFA6;">(Generic Service Host Process)</mark>

	is to act as a host for multiple dynamic-link libraries (DLLs) that implement various Windows services, **Service Hosting** , **Registry Entries** , **Registry Key**

 - **Executable Path:** `%SystemRoot%\System32\svchost.exe` (likely `C:\Windows\System32\svchost.exe`)
- **Parent Process:** `services.exe`
- **User Context:** Executed under the security context of `NT AUTHORITY\SYSTEM (S-1-5-18)`, `LOCAL SERVICE (S-1-5-19)`, or `NETWORK SERVICE (S-1-5-20)`
- **Base Priority:** `8` (indicating a relatively low base priority)
- **Time of Execution:** Varies

#### What is taskhost.exe ?
<mark style="background: #ADCCFFA6;">(generic host process)</mark>

	It plays a role in managing and executing various background tasks and services on the system,is to act as a host for processes that run from Dynamic Link Libraries (DLLs) instead of executable files (EXEs)

- **Executable Path:** `%SystemRoot%\System32\taskhost.exe` (likely `C:\Windows\System32\taskhost.exe`).
- **Parent Process:** `services.exe`
- **Username:** Varies, depending on the user context and the services being executed
- **Base Priority:** `8` (indicating a relatively low base priority)
- **Time of Execution:** Varies, as it depends on the specific tasks and services being performed

#### What is EXPLORER.EXE ?
<mark style="background: #ADCCFFA6;">(Windows Explorer)</mark>

	Functionality:Windows Explorer, responsible for the user's desktop, file access, file browsing, and launching files via their extensions.

- **Executable Path:** `%SystemRoot%\explorer.exe` (likely `C:\Windows\explorer.exe`).
- **Parent Process:** Created by `USERINIT.EXE`, but the parent process won't exist during observation
- **Username:** Varies, as it runs under the context of logged-on users
- **Base Priority:** `8` (indicating a relatively low base priority)
- **Time of Execution:** Varies, depending on user logon and system activity

In last these section emphasizes protecting vital Windows processes, particularly "explorer.exe," from malware. The checklist provides quick tips for spotting irregularities and stresses continuous vigilance against potential threats, with a focus on process location, digital signatures, and monitoring child processes

# << Endpoint Baselines >>

 يكتب الملخص عنهCHAT GPT تكلمنا قبل عن البيس لاين ما يحتاج اعيده بخلي 

		- **  
    Introduction to Baselining:**
    
    - Importance for enterprises in detecting anomalies.
    - Covers system processes, services, drivers, applications, and file structures
    
	- **Baseline Definition:**
    - A file for comparing current settings against a predefined state.
    - Used to identify anything out of place in a system.
	- **Practical Implementation using PowerShell:**
    
    - PowerShell demonstrated for creating and comparing baselines.
    - Example from the Hunting Web Shells module.
	- **Detecting Unauthorized Changes:**
    
    - Reference to change management principles.
    - Tools like File Integrity Monitoring (FIM) highlighted.
	- **FIM Products:**
    
    - Mention of FIM products like TripWire, SolarWinds, AlienVault, etc.
	- **Implementation with Appliances:**
    
    - Use of appliances for comparing artifacts to set configurations.
    - Reference to SCCM as an example.
	- **PowerShell Desired State Configuration (DSC):**
    
    - Alternative method for configuration baselines.
    - PowerShell's DSC for maintaining and standardizing configurations.
	- **Microsoft Security Compliance Tools:**
    
    - Introduction to Microsoft Security Compliance Manager and Toolkit.
    - Ready-to-deploy policies based on security recommendations.
	- **Example: Services Baselining with PowerShell:**
    
    - Using PowerShell cmdlets to baseline running services.
    - Comparison using the Compare-Object cmdlet.
	- **Tools and References:**
    
    - Mention of Puppet, Ansible, Chef for DSC understanding.
    - Introduction to Microsoft Security Compliance Toolkit.
	- **Analysis and Memory Analysis:**
    
    - Importance of process or service baselines for analysis.
    - Suggested PowerShell commands for service baseline creation and comparison.

End section

# << Malware Hunting >>
#### What is malware ?
	refers to any software intentionally designed to cause harm to a computer, server, network, or user

#### What is Viruses ?

	A computer virus is a self-replicating program that spreads without the owner's permission or knowledge. Unlike worms that exploit vulnerabilities, viruses rely on the host for propagation. If a file carrying a virus is moved to another system, the virus has an opportunity to spread and survive

**Sub-Types of Viruses:**

1. **Resident:** Executes and becomes memory resident, infecting other programs when triggered by specific events
2. **Non-Resident:** Searches for files to infect upon execution, quits afterward, and continues to find new targets when the infected program runs again
3. **Boot Sector:** Spreads via boot sectors, for example, when an infected CD-ROM is left in the drive during system shutdown, activating and spreading upon the next boot
4. **Multi-Partite:** Exhibits various infection mechanisms, combining features like Boot-Sector and Resident viruses for versatile spreading

#### What is Worm ?

	Worms are a type of software that exploits network or system vulnerabilities to autonomously spread from one system to another

#### What is Rootkits ?

	A rootkit is a type of stealthy malware designed to conceal or compromise a computer system at a deep level , Functioning as a complement to other malicious software, rootkits can hide processes, add files to the file system, implement backdoors, and create vulnerabilities

- **Application Level:** Replaces programs with copies of others
- **Library Level:** Controls shared libraries, affecting multiple applications
- **Kernel Level:** Common and resistant to removal, operates at the same privilege level as antivirus software
- **Hypervisor Level:** Utilizes virtualization technologies, such as blue pill and SubVirt
- **Firmware Level:** Targets firmware like BIOS, ACPI tables, and device ROMs, with a high chance of survival due to limited scanning tools

#### What is Bootkits

	Bootkits vs. Rootkits:
Bootkits differ by infiltrating the operating system before it fully starts, compromising security from the outset. This unique approach grants bootkits the ability to exert complete control over the target operating system.

#### What is Trojan ?

	masquerades as legitimate software while secretly enabling unauthorized access to the user's system. An example is downloading a game from the internet, which may contain hidden malicious code. While the user enjoys the game, the concealed code executes malicious activities in the background.


#### What is Backdoor ?

	is software enabling unauthorized access by bypassing authentication. It allows remote entry while remaining hidden, similar to Remote Access Trojans (RATs)

#### What is Sypware ? 

	gathers user information, monitoring online activities without consent. The collected data is sent to the spyware's author

#### What is Botnets ?

	are networks of compromised computers controlled by a central server. Created through malware installation, they can be used for DDoS attacks and spam distribution by the bot master, who issues commands to the bots

#### What is Ransomware ?

	encrypts files and demands payment in Bitcoin for the decryption key. It holds files hostage, requiring victims to pay a ransom to restore their data, earning the name extortive malware


#### What is Information Stealers ?

	illicitly acquires sensitive data like encryption keys, login credentials, credit card information, and proprietary data. The stolen data may be exploited for various malicious purposes

#### What is Keyloggers ?

	Keyloggers capture keystrokes as the victim is typing

#### What is Screen recorders? 

	are malicious software designed to capture and record screenshots of the active window on a victim's computer

#### What is RAM scrapers ?

	are malware designed to extract sensitive data, including login credentials, from a computer's random access memory (RAM)


And we have another malware 

Adware displays unwanted ads, Greyware causes undesired effects, Scareware tricks users with false threats, Fakeware deceives as legitimate software, and PUPs are potentially unwanted programs bundled with downloads.

# << 2.3 Malware Delivery >>


These are common vectors for malware distribution:

1. **Physical media:** Malware spread through CDs, USB drives, etc.
2. **Email (attachments):** Malicious software attached to emails.
3. **URL links:** Malicious links leading to malware downloads.
4. **Drive-by downloads:** Malware automatically downloaded from websites.
5. **Web advertising:** Malicious ads containing malware.
6. **Social media:** Malware spread through social platforms.
7. **File shares:** Malware distributed through shared files.

8. **Software vulnerabilities:** Exploiting weaknesses in software for malware delivery:re common exploitation techniques:
1. **Stack overflows:** Exploited by overflowing stack buffers to control the flow of execution and execute malicious code.
2. **Heap overflows:** Exploited by overwriting heap pointers to direct the execution to malicious code instead of its original location.


Additional, less common vectors include Malware Delivery:

1. **Peer-to-peer (P2P) file sharing**
2. **Instant messaging**

# <<  Malware Evasion Techniques >>

Malware employs various techniques to run, evade detection, and achieve its objectives, including privilege escalation, credential theft, data exfiltration, and persistence. Researchers and adversaries continuously discover new evasion methods. Staying informed about the latest techniques is essential for cybersecurity professionals

Explore MITRE ATT&CK for in-depth information on:

- [Exfiltration](https://attack.mitre.org/wiki/Exfiltration)
- [Persistence](https://attack.mitre.org/wiki/Persistence)
- [Technique Matrix](https://attack.mitre.org/wiki/Technique_Matrix)

One technique involves leveraging Alternate Data Streams (ADS), a feature of the NTFS file system. ADS can store metadata and other data streams, providing a covert method for concealing information within files. Understanding such evasion techniques is vital for effective threat hunting and cybersecurity.

For more details, refer to Microsoft's documentation on Alternate Data Streams in NTFS and the [CreateFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) and [WriteFile](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile) Windows API functions.


#### Injection 

various injection techniques used by malware to inject into processes will be discussed.

**DLL Injection:**

1. **Locate Process:** Malware finds a target process using Windows API.
2. **Open Process:** The malware opens the identified process.
3. **Allocate Memory:** Finds a location to write the path of the malicious DLL.
4. **Copy:** Writes the path to the malicious DLL into the allocated memory.
5. **Execute:** Executes the malicious DLL in another process by starting a new thread.

**Reflective DLL Injection:** A stealthier technique that loads the DLL in memory without relying on standard Windows API calls. The DLL maps itself into memory, resolving import addresses, fixing relocations, and calling DllMain without using LoadLibrary

**Thread Hijacking:**

1. **Locate Thread:** Malware finds a target thread to inject into
2. **Open Thread:** Opens the identified thread
3. **Suspend Thread:** Suspends the thread to inject
4. **Allocate Memory:** Finds a location to write the path of the malicious DLL or shellcode
5. **Copy:** Writes the path to the malicious DLL or shellcode into the allocated memory
6. **Resume Thread:** Resumes the thread after injection

**PE (Portable Executable) Injection:** Similar to DLL Injection but doesn't require the malicious DLL to reside on disk. Uses WriteProcessMemory to write the malicious code into the target location without using LoadLibrary.

These injection techniques allow malware to infiltrate and execute within processes, making detection and analysis challenging. Stay informed about the latest methods to enhance cybersecurity defenses.

1. **Hooking Events:**
- **Interception:** Malware intercepts events with SetWindowsHookEx()
- **Monitoring:** Monitors keyboard and mouse inputs, among others
- **DLL Loading:** Loads malicious DLLs based on specific events
- **Significance:** Enables covert actions like keylogging and executing additional payloads

Hook Injection enables malware to manipulate and respond to various system events, allowing for covert actions such as keylogging or executing additional malicious payloads.

**Kernel-Mode Rootkits: SSDT Hooks Overview:**

1. **SSDT Basics:**
    
    - SSDT (System Service Descriptor Table) aids Windows Kernel.
    - Entries point to essential kernel mode functions
2. **Kernel Mode Operations:**
    
    - Kernel functions correspond to SSDT entries.
    - SSDT exported as KeServiceDescriptorTable()
3. **SSDT Hooking:**
    
    - Globally modify SSDT pointers
    - Redirect system functions to rootkit-controlled location
4. **Implementation:**
    
    1. **Hook SSDT Entry:** Redirect specific function (e.g., NTQueryDirectoryFile)
    2. **Call Function:** Trigger malicious function on system function calls
    3. **Pass Control:** Invoke original function for results
    4. **Alter & Return Results:**
        - Modify results (e.g., hide a file) before returning

**Kernel Mode IRP Hooks\:**

- **IRPs Essential:** Windows kernel uses I/O Request Packets (IRPs) for data transmission
- **Universal Application:** IRPs are used by various components, such as network interfaces and drivers
- **DKOM Technique:** Direct Kernel Object Manipulation (DKOM) involves global hooking of function pointers in device objects
- **Systemwide Impact:** DKOM techniques globally affect the system, allowing for fundamental manipulation

Userland Rootkits

**IAT Hooks:**

- **Definition:** Import Address Table (IAT) resolves runtime dependencies
- **Role:** Lists needed API functions and their locations
- **Userland Impact:** IAT Hooking modifies the table, redirecting functions
- **Functionality:** Enables userland rootkits to control API calls in executables

**EAT Hooks** 

	modify the Export Address Table (EAT) in DLLs, housing support functions for executables. Unlike IAT Hooking, this technique primarily targets DLLs and is integral for maintaining functions accessible to other programs. It complements IAT Hooking and is specifically employed in DLLs under normal settings

**Inline Hooking**:

	 is a challenging technique where malware directly modifies the API function. By altering the initial bytes of the target function code, the malware inserts malicious code, redirecting the instruction pointer (EIP) to execute code from a different memory location.

Rootkits: Process Hiding:

	employ process hiding via SSDT hooking on NtOpenProcess to obscure their presence from the EPROCESS list. This involves detaching their structure from the list and, if necessary, from PsLoadedModuleList, making detection challenging for analysts.

masquerading

	 using names such as svch0st or residing in common directories like C:\Windows, to blend in and avoid detection. This simple yet effective tactic helps it appear innocuous and evade scrutiny by resembling legitimate processes.

Malware will also hide in other locations, such as in:
• Temporary folders 
• Temporary Internet files 
• Program Files

  Packing / Compression
  
	like UPX or custom ones, to compress executables. Originally designed for file size reduction, these tools lower pattern visibility, aiding in evading detection by antivirus products.

Recompiling

	specially using different compilers, aims to alter the executable's signature, such as an MD5 hash, to evade detection by security measures relying on specific signatures.


Obfuscation

	lters code to impede analysis and reverse engineering. Used by malware and legitimate software, it aims to protect functionality

Anti-reversing techniques

	employed by malware, aim to detect analysis and mislead analysts. Methods include identifying virtual machine environments, detecting attached debuggers, and inserting junk code for misdirection, prolonging analysis time.

# END
