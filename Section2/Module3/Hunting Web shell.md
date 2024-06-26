##### Intro

- **Definition and Purpose**: A web shell is a script that allows remote execution of commands on a victim's machine. Attackers use it to control the victim's system after a successful exploit, which is the post-exploitation stage
    
- **Deployment**: Attackers upload the web shell to the victim's web server. They often target servers within internal networks to enable pivoting, moving laterally to other systems in the network
    
- **Programming Language**: The web shell must be written in a programming language supported by the victim's web server, such as PHP for an Apache server. Attackers determine the server's language through information gathering
    
- **Execution Methods**: Common methods for deploying a web shell include XSS (Cross-Site Scripting), RFI (Remote File Inclusion), SQL Injection, and LFI (Local File Inclusion). Misconfigurations in the web server can also be exploited
    
- **Examples**: Notable web shells used in past attacks include C99
  
![Pasted image 20240623225004](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/5846f423-e69e-47e2-8a7e-27d244e4b4f3)

To download https://github.com/phpwebshell/c99shell

- B347K
To download https://github.com/b374k/b374k

-   R57

![Pasted image 20240623225454](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/5b671553-eab7-41de-898b-62a97dfc1c73)

To download https://github.com/tennc/webshell/blob/master/php/PHPshell/%E3%80%90r57%E3%80%91/r57.php

- Each varies based on the server's supported services and configurations
    
- **Bypassing Security**: Advanced attackers bypass Web Application Firewalls (WAF) and antivirus software by obfuscating the web shell's code or disguising it within other files to avoid detection
  ![Pasted image 20240623225817](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/4c1656f3-61af-4f93-8ccb-0423966bb2e3)

    
- **Detection**: WAF and antivirus programs use signature databases to detect malware. Skilled attackers modify web shell signatures to evade detection
---

#### Hunting Tools\

The first tool we will mention here is Simple LOKI. This is a simple tool that helps identify IOCs, which are Indicators of Compromise, signs of malware presence on your device. This tool scans files or folders on the web server and highlights any indicators suggesting the presence of a web shell
https://github.com/Neo23x0/Loki

![Pasted image 20240623231216](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/da5fd3b4-8685-4c2e-a534-e504d22662bc)


The tool works by searching for IOCs on your system and providing alerts. It scans for MD5, SHA1, and SHA256 hashes, checks their signatures, and ensures their security. Additionally, it can use YARA rules, which are included in its base data from the YARA tool, to detect malicious traffic or any malware attempting to infiltrate your network, providing alerts accordingly.

MD5, SHA1, and SHA256 
![Pasted image 20240623231250](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/781dfd41-9426-4a65-babe-25ab8a2fcef1)
Generated log file
![Pasted image 20240623231513](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/bcae3e97-0610-4e7c-9b6f-2375dcc0af2f)


Moreover, the tool can perform hard and soft filename indicator checks using regular expressions, meaning it examines all the files on your system to detect anything suspicious.

![Pasted image 20240623231537](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/8d49c1e8-df81-4354-8985-0ef74f7d7b3f)

Loki detected suspicious objects here

![Pasted image 20240623232407](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/01857ddc-4e92-4ce3-8e6b-172078d3cef0)

##### NeoPI

This is a Python script designed to uncover obfuscated content, meaning it can detect hidden malicious content. It can also analyze text files, even if they are encrypted, and identify any suspicious elements. NeoPI checks scripting files like .py, .php, or any other script files to see if they contain hidden web shells.

[GitHub - CiscoCXSecurity/NeoPI](https://github.com/CiscoCXSecurity/NeoPI)

![Pasted image 20240623232628](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/06469c56-26f1-4502-86af-2e3b6f9d361c)


Here’s how NeoPI works:

- NeoPI operates through a command-line interface.
- It scans a specified folder on the web server
- The tool generates a report listing suspicious files. As a threat hunter, you can then perform a detailed investigation on these flagged files. The report will highlight the top 10 files that look suspicious (IC 10 top files), along with a list of files that are deemed safe.
![[Pasted image 20240623232628.png]]
Detailed steps and features:

	- NeoPI identifies the top 10 longest files by size. It flags larger PHP files as potentially suspicious because larger files may contain web shells. This is a prompt for you to investigate these files further.
- It also ranks files based on the level of suspicion, indicating how likely it is that they contain something malicious, such as a web shell. These files are listed in order of risk, helping you prioritize your investigation. If a file is confirmed to be malicious, you should take steps to close or remove it.

#### BackDoor man

**Man BackDoor:**

- **Description:** A toolkit written in Python to detect suspicious, hidden, and malicious PHP scripts, especially web shells.
- **Features:**
    - Detects through file names.
    - Uses a signature database to identify known web shells and backdoors.
    - Detects suspicious PHP activities and functions that could indicate a web shell.
    - Integrates with VirusTotal for regular updates.
- **Usage:** Operates via command-line interface, scans web server directories, flags suspicious files, and prioritizes them for investigation.
[GitHub - cys3c/BackdoorMan: BackdoorMan is a toolkit that helps you find malicious, hidden and suspicious PHP scripts and shells in a chosen destination.](https://github.com/cys3c/BackdoorMan)

#### PHP Malware Finder

- **Description:** A script used to detect obfuscated code, particularly in PHP functions used in web shells.
- **Features:**
    - Identifies obfuscated PHP code that could be hiding malicious activities.
    - Matches detected code against the YARA tool's base data to determine if a file is malicious or not.

This tool helps in identifying hidden malicious code within PHP scripts, providing a crucial step in ensuring web server security

[GitHub - nbs-system/php-malware-finder](https://github.com/nbs-system/php-malware-finder)


#### PHP UN
- **Description:** A tool designed to de-obfuscate PHP code.
- **Features:**
    - Converts obfuscated PHP code back into a readable format, making it easier to analyze and understand.

This tool is useful for reversing obfuscation in PHP scripts, allowing security professionals to inspect the original code and identify any hidden malicious activities

[UnPHP - The Online PHP Decoder](https://www.unphp.net/)

#### Web Shell Detector

- **Description:** The Shell Web Detector tool is commonly used by Blue Teams in Security Operations Centers (SOCs). Its primary function is to detect various types of web shells, such as those written in PHP, Perl, ASP, or ASPX.
- **Features:**
    - **Multi-Type Support:** It supports detection for a wide range of web shell types, enhancing its versatility and applicability across different environments.
    - **Signature Database:** The tool includes a comprehensive database of known and discovered signatures for web shells. This allows it to match patterns and characteristics against these signatures to identify potential web shell instances.
    - **Advanced Capabilities:** Due to its ability to handle multiple types of shells and its extensive signature database, it is considered an advanced tool in the field of web shell detection. However, accurately determining whether a detected file is indeed a web shell can still be challenging in some cases, requiring further investigation by security analysts.

This tool plays a crucial role in proactive threat detection and incident response strategies within SOC environments, aiding in the identification and mitigation of web shell-based threats

#### Detect malware Linux

tool is designed to scan and identify malicious software specifically targeting Linux systems. It enhances security by detecting viruses, trojans, and other malware types, contributing to proactive defense against potential security breaches in Linux environments

#### Invoke ExchangeWebShellHunter

known as Web Shell Hunter, is used for hunting down web shells that may compromise Microsoft Server Exchange. This server type is a critical component in Microsoft's email infrastructure. If there is suspicion or concern about the presence of a web shell on a Microsoft Server Exchange system, this tool can be employed to detect and mitigate such threats effectively
[GitHub - FixTheExchange/Invoke-ExchangeWebShellHunter: PowerShell script for hunting webshells on Microsoft Exchange Servers.](https://github.com/FixTheExchange/Invoke-ExchangeWebShellHunter)

#### NPROCWATCH

is a proactive security tool designed to detect and respond to web shell activities on servers, particularly focusing on identifying and neutralizing newly created processes associated with such malicious entities

---

### Hunting Web Shells

### Log Files Analysis

1. **Initial Step**: Always check log files first when hunting for web shells. These files often record when new files are created or added to the server, and log the IP address of the entity that made the changes.
2. **Log Parser Tool**: Instead of manually checking log files on each server, use a tool like Log Parser Studio. This tool can automate the analysis, scanning for newly added files within a specified time frame.

### Commands for Windows and Linux Servers

1. **Environment**:
    
    - Windows servers typically run on IIS.
    - Linux servers typically run on Apache.
    - Courses like Linux+ and MCSA provide detailed information on these servers.
2. **Example Scenario**:
    
    - Assume we have four files (two are clear web shells, two are suspicious).
    - Web shell files:
        - `locus7s.php` located at `/var/www/html/v1/locus7s.php`.
        - `ss8.txt` located at `/var/html/v1/imags/ss8.txt`.
    - Suspicious files:
        - `unknown.txt` located at `/var/www/html/v1/js/unknown.txt`.
        - `unknown2.php` located at `/var/www/html/v1/css/unknown2.PHP`.
3. **Using Commands for Detection**:
    
    - **Linux Commands**:
        
        - To find newly added PHP files in the last 24 hours:
            
            `find . -type f -name '*.php' -mtime -1` or
            `find . –type f –name ‘*.txt’ –mtime -1 
	        
            ls –la to also view hidden entries
        - Explanation: This command searches for files (`-type f`) in the current directory (`.`) with the extension `.php` modified in the last day (`-mtime -1`).
    - **Analyzing Files**:
        
        - Look inside PHP files for suspicious functions like `eval`, which are often used maliciously:
             
            `find . -type f -name '*.php' | xargs grep -I "eval *("`
            
        - Similarly, search for `base64_decode`, another function commonly misused in web shells:
            
            `find . -type f -name '*.php' | xargs grep -I "base64_decode("`
             **xargs : build and execute command lines from standard input**
             **grep : prints lines matching a pattern**
			
4. **Additional Functions to Look For**:
    
    - `mail()`: Often used for sending spam.
    - `fsockopen()`, `pfsockopen()`: Used for opening ports.
    - `exec()`, `system()`, `passthru()`: Used for executing commands remotely.
    - Combine the search into one command:
        
        ``find . -type f -name "*.php" | xargs egrep -l "(mail|fsockopen|pfsockopen|exec|system|passthru|eval|base64_decode) *\("``
        

### Windows Server Commands

1. **PowerShell Commands**:
    - To find PHP files recursively:
        
        `Get-ChildItem -Recurse -Include *.php | Select-String -Pattern "eval|base64_decode|mail|fsockopen|pfsockopen|exec|system|passthru" | Out-GridView`
        

### Tools for Web Shell Detection

1. **LOKI**:
    
    - Use LOKI to scan for known signatures of web shells. Provide it with the web server directory (e.g., `/var/www/html/`).
    - LOKI uses YARA rules for detection and relies on a signature database to identify malicious files.
    - Example directory for YARA rules in LOKI: `/loki/signature-base/yara`.
2. **NeoPI**:
    
    - NeoPI is a Python script used to detect malicious files by calculating file entropy and comparing against known signatures.
    - Provide it with the web server directory to scan (e.g., `/var/www/html/`).
    - NeoPI can detect more files compared to LOKI by looking into the file content for suspicious functions.
