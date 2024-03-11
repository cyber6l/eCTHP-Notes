###### اليوم بنكمل ونتكلم عن المالوير اكثر
 

# << Malware Persistence >>

#### Autostart Locations

	are places on a computer where programs can launch automatically. Malware exploits these spots to start with the system.

such as common autostart in the Windows registry :
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`

such as common Windows NT registry :

`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`

`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

To download AutoRuns from the official Microsoft Sysinternals website
[AutoRuns Download](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)



#### Scheduled Task

	Task scheduling is a versatile technique often exploited by adversaries for various purposes beyond just persistence.

-  The command aims to create a scheduled task on a Windows system.
`schtasks /create /tn "mysc" /tr C:\Users\Public\test.exe /sc ONLOGON /ru "System"
`
- **schtasks**: Manages scheduled tasks in Windows
- **/create**: Initiates the creation of a new scheduled task
- **/tn "mysc"**: Names the task as "mysc.
- **/tr C:\Users\Public\test.exe**: Sets the path to the executable or script (test.exe) that the task will run
- **/sc ONLOGON**: Triggers the task to run when any user logs on
- **/ru "System"**: Specifies that the task will run under the "System" user account

#### COM Hijacking

	Adversaries manipulate the Microsoft Component Object Model (COM) to insert malicious code, redirecting the execution flow and enabling them to run their code instead of legitimate software on Windows

You can read the ATT&CK document here [MITRE ATT&CK T1546.015](https://attack.mitre.org/techniques/T1546/015/)


#### DLL Hijacking

	DLL Hijacking, exploiting the Windows DLL search order. When an executable runs, it searches for required DLLs, starting locally and progressing to C:\Windows\System32. Attackers can manipulate this process by placing a malicious DLL with the expected name, leading to its unintended loading. Sub-techniques include Phantom DLL attacks and Side Loading using the WinSxS folder. These tactics compromise system integrity and evade detection

For more 4u 
1. [ATT&CK T1038: DLL Hijacking](https://attack.mitre.org/wiki/Technique/T1038)
2. [ATT&CK T1073: DLL Side-Loading](https://attack.mitre.org/wiki/Technique/T1073)
3. [FireEye PDF: DLL Side-Loading](https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf)
4. [BleepingComputer: How Malware Hides as a Service](https://www.bleepingcomputer.com/tutorials/how-malware-hides-as-a-service/)

#### Windows Services

	Malicious services, created using the "sc" command, are a favored persistence method. They run at boot, often preceding antivirus software. Attackers replace existing services, exploit weak ACL configurations, or configure recovery actions to execute malware upon service failure

[Microsoft Docs: Service Replacement](https://technet.microsoft.com/en-us/library/cc753662(v=ws.11).aspx)
##### END Section 2 In Module 3

# << Hunting Malware >>

## Detection Tools 


###### What is PE Capture ?

	PE Capture tool logs and saves loaded PE files, executables, DLLs, and drivers, aiding in real-time analysis for potential malicious activity

[NoVirusThanks PE Capture](http://www.novirusthanks.org/products/pe-capture-service/)


###### What is ProcScan.rb ?

	a Ruby tool, scans process memory for code injection but is limited to 32-bit systems. The output identifies potential code injection within a specific thread of the rundll32 process. While the tool lacks PID information, PowerShell can be used to obtain it along with a list of running processes and their thread IDs.

[ProcScan on GitHub](https://github.com/abhisek/RandomCode/tree/master/Malware/Process)

###### What is Meterpreter Payload Detection ?

	is a tool designed to scan all running processes on a system to detect the presence of Meterpreter. The tool can be downloaded for use

[Meterpreter Payload Detection on GitHub](https://github.com/DamonMohammadbagher/Meterpreter_Payload_Detection)

###### What is Reflective Injection Detection ?

	is a tool designed to detect reflective DLL injections in memory by analyzing PE headers. It dumps information about the injected process and other unlinked executable pages to the root folder

[Reflective Injection Detection on GitHub](https://github.com/papadp/reflective-injection-detection)

###### What is PowerShell Arsenal ?

	designed for reverse engineering. It aids in disassembling managed and unmanaged code, performing .NET malware analysis, memory analysis, file format parsing, and extracting system information

###### What is Get-InjectedThread.ps1 ?

	is a PowerShell tool designed to detect code injection by scanning active threads on the system. It retrieves the starting address of specific functions, like NTQueryInformationThread, flagging any identified executable code as injected

[Get-InjectedThread.ps1 Download](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)


# << 3.3 Detection Techniques >>

###### What is Fuzzy Hashing ?

	utilizing programs like SSDeep, computes context-triggered piecewise hashes (CTPH) that can match inputs with identical byte sequences, even if interspersed with differing content. This technique breaks files into smaller pieces for examination rather than analyzing the entire file. VirusTotal utilizes SSDeep for fuzzy hashing, providing output during file analysis


 [DFRWS Paper: Identifying Almost Identical Files Using Context-Triggered Piecewise Hashing](http://dfrws.org/sites/default/files/session-files/paper-identifying_almost_identical_files_using_context_triggered_piecewise_hashing.pdf)
 
[DFIR Science: How To - Fuzzy Hashing with SSDEEP (Similarity Matching)](https://dfir.science/2017/07/How-To-Fuzzy-Hashing-with-SSDEEP-(similarity-matching).html)

[SSDeep GitHub Repository](https://github.com/ssdeep-project/ssdeep)

###### What is Import Hashing ?

	coined by Mandiant and implemented by VirusTotal, involves creating a hash based on the library/API names and their specific order within a portable executable (PE) file's import table. This technique is used to track and identify related malware samples by their import structures


[VirusTotal Blog: Imphash](http://blog.virustotal.com/2014/02/virustotal-imphash.html)

[FireEye Blog: Tracking Malware with Import Hashing](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html)

[ImpHash Generator GitHub Repository](https://github.com/Neo23x0/ImpHash-Generator)

###### What is Execution Tracing ?

	designed to track compatibility issues with executed programs and store file metadata, is a key forensic element. Mandiant's ShimCacheParser, released five years ago, aids in gathering ShimCache metadata for Windows investigations.

 [AppCompatProcessor Blog](https://www.fireeye.com/blog/threat-research/2017/04/appcompatprocessor.html)

[AppCompatProcessor GitHub Repository](https://github.com/mbevilacqua/appcompatprocessor)

# <<  Memory Analysis >>

	in cybersecurity provides insight into a system's runtime state, uncovering processes, network connections, and potential malware activities. Acquiring memory, essential for analysis, can be achieved through hardware or software methods
	
**Toolset for Memory Analysis:**

1. [FTK Imager Download](https://accessdata.com/product-download/ftk-imager-version-4-2-0)
2. [DumpIt](https://my.comae.com/)
3. [Magnet RAM Capture](https://www.magnetforensics.com/resources/magnet-ram-capture/)
4. [Mandiant’s (FireEye) Redline](https://www.fireeye.com/services/freeware/redline.htm)

###### What is Redline ?

	is a GUI-based memory analysis tool that facilitates comprehensive auditing and collection of system data, including processes, drivers, file-system metadata, registry data, event logs, network information, services, tasks, and web history. It automates anomaly detection, IOC analysis, and provides a quick overview of a system's memory to identify rogue processes, injections, rootkits, etc., using the MRI Score Index. The tool offers various views, including Processes View, Hierarchical Processes View, Handles, Memory Sections, Strings, and Ports. Redline is effective for triaging and can be followed up with more advanced tools like Volatility for in-depth analysis.

###### What is Volatility ?

	is a potent memory analysis tool, less user-friendly than Redline but effective. It's available for Windows, Linux, and Mac OS, written in Python. Key parameters are memory dump file, OS Profile, and Plugin. It has 200+ default plugins, enabling custom additions. Notable plugins include "pslist," "psscan," "psxview," "pstree," and "malfind" for processes, hidden processes, process relationships, and code injection detection. Code injection techniques like DLL Injection and Reflective Injection are covered. Volatility's plugins analyze system objects, and it offers modules to extract malicious objects for detailed analysis

- [Volatility 3 CheatSheet](https://blog.onfvp.com/post/volatility-cheatsheet/)
- [Volatility Usage](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage)
- [Memory Samples for Practice](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)
- [Rootkit Detection Example](https://eforensicsmag.com/finding-advanced-malware-using-volatility/)

### Live System Memory Hunting ?

	Tools have been developed to scale memory hunting by detecting injected code on live machines without acquiring memory dumps
	
Three notable tools are:
1. [GetInjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
2. [Memhunter](https://github.com/marcosd4h/memhunter)
3. [Captain](https://github.com/y3n11/Captain)

###### What is Get-InjectedThread ?

	is a tool designed to detect various injection techniques on live systems. It can identify:
- Classic Injection
- Reflective DLL Injection
- Memory Module (similar technique to RDI)

you can refer to the [original presentation of the tool](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2).
###### What is Memhunter ?

	is a tool designed for live system memory hunting. For a practical demonstration and a working Proof of Concept

you can watch the tool in action on [YouTube](https://www.youtube.com/watch?v=t_fR1sCENkc)

###### What is **Captain** ?

 is a tool with four key components:

1. **Monitor.ps1:** Monitors process creations and injects Captain.dll.
2. **Injector.exe:** Injects Captain.dll into processes.
3. **Captain.dll:** Hooks Windows API functions, logging events.
4. **Behan.py:** Analyzes Captain.dll events using provided signatures for alerting.

# THE END 

