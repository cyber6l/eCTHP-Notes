
#### اليوم نبدأ بسكشن جديد وممتع

 [<img src='https://cdn.jsdelivr.net/npm/simple-icons@3.0.1/icons/linkedin.svg' alt='linkedin' height='40'>](https://www.linkedin.com/in/talal-alqahtani-b757b1269/)  [<img src='https://cdn.jsdelivr.net/npm/simple-icons@3.0.1/icons/twitter.svg' alt='twitter' height='40'>](https://twitter.com/@cyber6l) 

# << Hunting Web Shells >>

وش الويب شيل؟ 

	A web shell is a malicious script that, when uploaded to a web server, allows unauthorized remote control, enabling attackers to manipulate the server, gain access to data, and pivot to other internal hosts.

The most common web shells are : PHP and ASP ولكن منت ملزوم فيها على حسب اي اللغه المستخدمه بالويب 

We have a lot of ways to upload a web shell onto the 
web server of interest:
1. XSS (Cross Site Scripting)
2. SQLi (SQL Injection)
3. RFI (Remote File Inclusion) or LFI (Local File Inclusion)
4. incorrect configurations on the web server
such as 
![13](https://github.com/cyber6l/eCTHP/assets/131306259/2b894599-f1fb-4f44-a6c1-ce1fc8772f8e)

امم طيب وش يفيدني او بالاخص كيف ابحث عن hunt for web ?

A lot wallah like:

1.  Deploy honeypots to attract and identify attackers. تنقفط سريع شينه يا الاتاكر
2. Use file integrity monitoring tools to detect unauthorized changes
3. Conduct regular security audits and vulnerability scans
4. Implement anomaly detection for unusual activities
5. Ensure that your web applications validate and sanitize user inputs to prevent common attack vectors like file upload vulnerabilities.
وهلم جرا 

# << 3.2 Hunting Tools >>

###### What is a LOKI ?

	LOKI is a security tool designed to simplify the process of scanning systems for known Indicators of Compromise (IOCs).
	
 IOC types include:
 
 Hashes:  ( providing a way to check files for known malicious signatures )
MD5
SHA1
SHA256

YARA: ( Applied to file data and process memory )
The tool supports Yara Rules, allowing users to define custom rules for identifying patterns associated with specific threats in both file data and process memory

Hard Indicator Filenames: Based on Regular Expressions
This can include specific file naming conventions associated with known threats

Soft Indicator Filenames: Based on Regular Expressions
This provides a more flexible approach to identifying potential threats

Can be downloaded from  [GitHub - Neo23x0/Loki: Loki - Simple IOC and YARA Scanner](https://github.com/Neo23x0/Loki)

###### What is a NeoIP ?
*Assist in the detection of hidden web shell code.*

	 NeoPI is a Python script designed for the purpose of detecting obfuscated and encrypted content within text or script files. The tool employs a variety of statistical methods to analyze the content and identify patterns indicative of obfuscation or encryption techniques.

1. **Detection Methods:**
    
    - NeoPI uses statistical methods to identify patterns associated with obfuscation and encryption in text and script files.
2. **File Type Focus:**
    
    - The tool is specifically tailored for detecting hidden web shell code within files.
3. **Python Script:**
    
    - NeoPI is implemented as a Python script, making it versatile and easy to use for users familiar with Python.

Can be downloaded from    [GitHub - CiscoCXSecurity/NeoPI](https://github.com/CiscoCXSecurity/NeoPI)

Note: NeoPI will produce an output based on the following: 
• Top 10 IC files  • Top 10 signature match counts 
• Top 10 longest word files • Top 10 entropic files 
• Top 10 SUPER-signature match counts  • Top cumulative ranked files


###### What is a BackdoorMan

	 Users can use BackdoorMan by providing a target destination, and the toolkit will analyze the PHP files within that location. It employs various methods and signatures to identify patterns commonly associated with malicious scripts, including backdoors and shells.

Can be downloaded from [GitHub - cys3c/BackdoorMan: BackdoorMan is a toolkit that helps you find malicious, hidden and suspicious PHP scripts and shells in a chosen destination.](https://github.com/cys3c/BackdoorMan)

 2 functions flagged in this particular PHP file:
• php_uname • popen <img width="451" alt="Screenshot 2024-03-10 142633" src="https://github.com/cyber6l/eCTHP/assets/131306259/389db085-d162-44b9-bcee-2c3372898633">

Additional functions that the script has flagged
• exec • system • passthru • base64_decode

###### What is a PHP-Malware-Finder ?

	 is a security tool crafted to identify and flag potentially malicious PHP scripts within a specified directory or web application. It aims to assist system administrators, developers,etc

Usage :
Users can run PHP-Malware-Finder by providing the target directory or path containing PHP files for analysis.

Can be downloaded from [GitHub - nbs-system/php-malware-finder](https://github.com/nbs-system/php-malware-finder)

###### What is a unPHP ?

	unPHP is a web-based service designed to deobfuscate and analyze PHP code. It helps developers and security professionals understand and recover the original, readable PHP code from obfuscated or encoded versions.

Usage : 
1. **Access the Website:**
    
    - Visit the unPHP website using a web browser.
2. **Input or Upload Code:**
    
    - Paste or upload the obfuscated PHP code into the provided interface.
3. **Initiate Deobfuscation:**
    
    - Trigger the deobfuscation process on the website.
4. **Review Results:**
    
    - The service will attempt to deobfuscate the PHP code, and you can review the results for a more readable version.
5. **Understand Code:**
    
    - Gain insights into the original functionality of the PHP code.

Can be downloaded from [UnPHP - The Online PHP Decoder](https://www.unphp.net/)

######  What is a Web Shell Detector ?

	 is a security tool designed to identify the presence of malicious web shells on a server. Web shells are scripts or code snippets that are illicitly uploaded to a web server, allowing unauthorized access and control.

Usage : 
1. **Download & Install:**
    
    - Download from a reliable source and install the Web Shell Detector.
2. **Configuration:**
    
    - Configure by specifying the target directory or files to scan.
3. **Run Scanner:**
    
    - Execute the tool to scan for potential web shells.
4. **Analysis:**
    
    - Identify malicious web shells using predefined patterns.
5. **Review Report:**
    
    - Examine the generated report for details on detected web shells.
6. **Take Action:**
    
    - If found, take appropriate action (remove or isolate malicious files).

Can be access from [Web Shell Detector](https://www.shelldetector.com/)

###### What is LMD ?

	Linux Malware Detect (LMD) is a malware scanner designed for Linux-based systems. It offers features for detecting and removing malicious software to enhance the security of Linux servers and environments.

Usage :
Scan all users' home directories for potential malware

	sudo maldet -a /home?/?/public_html

Clean (remove malware code from) detected infected files

	sudo maldet -q SCAN_ID -c

Exclude specific files or directories from future scans

	sudo maldet --config-option quar_hits_ignore_file "file_path"

You can read more   [Linux Malware Detect – R-fx Networks (rfxn.com)](https://www.rfxn.com/projects/linux-malware-detect/)
###### What is Invoke-ExchangeWebShellHunter ?

	is a PowerShell script likely developed for identifying and detecting web shells within Microsoft Exchange environments

**Features:**

- PowerShell-based: Implemented as a PowerShell script for compatibility with Microsoft Exchange environments.
- Web Shell Detection: Focuses on scanning for and identifying signs of web shells within the Exchange server.

You can access the script from [GitHub - FixTheExchange/Invoke-ExchangeWebShellHunter: PowerShell script for hunting webshells on Microsoft Exchange Servers.](https://github.com/FixTheExchange/Invoke-ExchangeWebShellHunter)

###### What is NPROCWATCH ?

	If it's a tool or script related to monitoring or managing processes on a Linux system

Usage : 
System administrators might use NPROCWATCH to ensure optimal system performance and prevent issues related to resource exhaustion.

To download [[ UDURRANI ]](https://udurrani.com/0fff/tl.html)

# << 3.3 Hunting Web Shells >>

#### Linux Commands

	 root@ubuntu : Iva r/www/html# find . –type f –name ‘*.php’ –mtime -1
- `find`: Command for searching files and directories.
- `.`: Starting directory for the search (current directory).
- `-type f`: Specifies to consider only regular files.
- `-name '*.php'`: Filters files with names ending in ".php".
- `-mtime -1`: Filters files modified within the last day.

وعشان يسهل عليك تبحث بالكوماند فيه اوامر تساعدك مثل
- `-grep`: prints lines matching a pattern
- `-xargs` : build and execute command lines from standard input

		find . -type f -name '*.php' | xargs grep -l "base64_decode("

- `find . -type f -name '*.php'`: Finds all regular PHP files in the current directory and its subdirectories.
- `|`: Takes the output of the left command and uses it as input for the right command.
- `xargs`: Converts standard input into arguments for a command.
- `grep -l "base64_decode("`: Searches for the pattern "base64_decode(" in the PHP files and prints only the names of files that contain this pattern.

• mail : can be used to send spam 
• fsockopen : can be used to open a network connect to send remote requests
• pfsockopen : same as fsockopen
• exec : this is for command execution 
• system & passthru : can be used with exec
#### Windows Commands

الموضوع بالويندز نفس الشي اللهم ان الكومندات تختلف زي ما كنا نسوي 
grep in <mark style="background: #FF5582A6;">Kali</mark>  = ) Select-String in <mark style="background: #FF5582A6;">Windows</mark>

• Get-ChildItem (like ls)
• Recurse :will go through all sub-directories of the root directory
• Include :will instruct PowerShell only to check a specific file type
• (pipe): its usage is similar to CMD and Linux
• \b is a word boundary instructing PowerShell to stop exactly at that word
• % {“$($_.filename:$($_.line)”} outputs the file name and line the word was found in
• Out-Gridview will display the output in a grid view format instead of console

رح اسكب العملي السلايدات بنوصله في الجزء الاخير من اليوم


#### File Stacking
	 is a technique that will help us identify files that are changed or newly created within the existing file structure that can potentially be malicious.

for example PowerShell code 

	Param([Parameter (Position—D , Mandatory=$True) ]
	[String[] ] 
	$searchPath
	)
	Get—Childltem $searchPath —Recurse —File | Select—Object fullname , length, lastwritetime | Out—GridView 
بشرح لك الكود
- `Param`: Defines parameters for the script or function.
    - `[Parameter(Position=0, Mandatory=$True)]`: Defines a mandatory parameter named `$searchPath` at position 0.
    - `[String[]] $searchPath`: Specifies that `$searchPath` should be an array of strings.
- `Get-ChildItem $searchPath -Recurse -File`: Uses `Get-ChildItem` to retrieve files recursively from the specified path(s).
    
- `Select-Object FullName, Length, LastWriteTime`: Selects specific properties (full name, length, last write time) from the file objects.
    
- `Out-GridView`: Displays the selected file information in a grid view for easy viewing.

#### Baselines
	within organization will help you to find anomalies within system processes, services, drivers, installed applications, file structures, etc.

#### Statistical Analysis
	A hidden web shell can quickly rise to the top of our ‘haystack’ based on times of execution, meaning that the file was accessed far beyond the number of times the other files were accessed/executed or vice versa

#### exiftool

	reading, writing, and editing metadata information in digital files, particularly images. It supports a wide range of file formats, including various image, audio, and video formats

To download [ExifTool by Phil Harvey](https://exiftool.org/)

#### W3WP Parent-Child Detection

	“An Internet Information Services (IIS) worker process is a windows process (w3wp.exe) which runs Web applications and is responsible for handling requests sent to a Web Server for a specific application pool.”

خلصنا النظري 

# << Lab Hunting Web Shells Part 1 >>

   into packet PCAPاول شي ب نسوي لود لل 
   *Task 1*

	Open NetworkMiner then going to Desktop > PCAPs > 1st

بعدين بنسوي تحليل لل PCAPs

	Load the 1st PCAP into Network Miner and inspect the details in the Hosts Tab
	then we must expand the Host Details section
	we have identified 2 machines:
1. A Linux box (172.16.5.20)
2. A Windows Web Server (10.100.0.100)

		expand Open TCP Ports within the Hosts tab in 10.100.0.100
		open the Parameters tab , "ieee"ونفلتر باستخدام  
		بتشوف قيم غريبه سكبها وركز على شي مشبوه وتبحث بداخله 
		روح للكيبورد اكتب مثلا shell or meta or metepreter and so on وسو لها اضافه
		open PCAP again and see if we can tell what kind of web shells were being used
		طف وشغل النيتورك مانير مره ثانيه ورح لل الملفات تاب
		
<img width="562" alt="Screenshot 2024-03-10 160716" src="https://github.com/cyber6l/eCTHP/assets/131306259/4b713337-587e-4469-98c8-380a8e52cb5e">
	 Interesting the file called c99_locus7s[2].txt  تم القفط c99
	لحد ما تحصل شي ثاني اذا ما حصلت غير الفلتره c99 بتوقف لا كمل ندور يلا نفلتر على  
	 shell and locus7s جرب تفلتر ب 
	 بس هيه لا تنسى تضيفها  
							 
<img width="129" alt="Screenshot 2024-03-10 161526" src="https://github.com/cyber6l/eCTHP/assets/131306259/ebf97c5a-cb4d-4815-a393-f2ce41c72c8f">	 

		الحين نرجع للقرش المتوحش
		Load the الاوللل PCAP in Wireshark to see what we find. then go to File > Open > Desktop > PCAPs > 1st.
		وعشان نطلع اي شي متعلق ب PCAPs 
		we well using Analyze > Expert Information and inspect the information provided
		Click on the traffic on port 4444 or 5555 تشوف اذا فيه شي مهم او لا
		بالاخير اتوقع انه 
		EXE created by MSF Venom.
In 1st PCAP
We used Ports 8080, 4444, & 5555 
What suspicious information do we see when we expand? HTTP Get request
Remote File Inclusion وش طبقنا اتاك ؟ 
وبرضو شفنا استضافه لملفات مشبوهه واساميها غريبه
طيب حصلنا شي او لقطنا حاجه ؟ يب استخدمنا الكيبورد ب النيتورك مانير

In 2st PCAP
جبنا c99 واستخدمنا غيرها
port 5555 ? An executable

*Task 2*
رح نبحث عن txt or php files on IIS server
نفتح السيرفر ونشغله
<img width="631" alt="Screenshot 2024-03-10 170621" src="https://github.com/cyber6l/eCTHP/assets/131306259/82b75fb6-668d-4a78-8c17-593881854888">
طبعا ما حصلنا php
بس لقينا txt files for Sh3ll5  &  C99

run of the foocompany directory

	loki 0_.22.0>loki.exe —p c : inetpub\wwwroot\foocompany
برضو مافي php 
 9c9.txt بس حصلنا ديكود 
 لان حصلنا دليل
 
جا وقت انه نستخدم NeoIP 

	NeoPI >python neopi.py —a c : inetpub\wwwroot\members

<img width="535" alt="Screenshot 2024-03-10 171752" src="https://github.com/cyber6l/eCTHP/assets/131306259/0286cf2c-3fe6-4936-b1e0-1c5fe0f5b103">
حصلنا ذول وش بنسوي الحين

Run NeoPI on folder foocompany

	NeoPI >python neopi.py —a c: Ninetpub\wwwroot\foocompany 

وطلع لنا الديكود 
 indeed web shells or potential web shells ولكن لازم تحدد منهم مين
تعال معي نكتب وش طلع معنا 

**Members folder**:
- nothing.php
- js/animal_shell_poc.php
- logs/New Text Document.txt
- images/c99.txt
- blah/sh3ll5.txt

**Foocompany folder**:
- shhh3llllz.txt
- decoded-9c9.txt
- nothing.php

بنسخدم اداه ثانيه تساعدنا لكن مارح اعلمك وش ارجع للاب ^_^

ولا اقولك استخدم exiftool for image < jpg

	**Path: C:\inetpub\wwwroot\foocompany\images\pic2x.jpg**

طبقها وشوف وش يطلع لك

ولكن ما تلاحظ ضيعنا وقتنا بواير شارك ؟ ولا شي استفدنا منه باللاب ذا 
Network Miner كل الاشياء المهمه طلعت لنا ب
 
وبكذا انتهينا الللاب 




 
