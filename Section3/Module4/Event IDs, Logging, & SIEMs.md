
1. **Introduction**
    
    - Event logs, initially used for troubleshooting, have become vital for incident response and threat hunting.
2. **Windows Event Logs** 
    
    - Core event logs in Windows include Application, System, and Security logs.
    - Logs capture various events such as application errors, system processes, and security-related actions.
    - Modern Windows versions use the EVTX format for logs.
    - Additional logs include Setup, Forwarded Events, and Applications and Services logs.
3. **Windows Event IDs**
    
    - Specific event IDs are crucial for monitoring account logon events, account management, and logon types.
    - Examples of important event IDs include:
        - 4624: Successful logon
        - 4625: Failed logon
        - 4634: Successful logoff
        - 4672: Special privileges assigned
        - 4720: Account created
    - Logon types provide context on how an account logged in, such as interactive, network, or service logons.
    - Logon IDs help track session information across different events.
4. **Windows Event Forwarding**
    
    - Discusses centralizing logs from multiple machines for better monitoring and analysis.
5. **Windows Log Rotation & Clearing**
    
    - Methods and best practices for managing log sizes and retention.
6. **Tools**
    
    - Lists and explains various tools used for log analysis and event monitoring.
7. **Advanced Hunting**
    
    - Techniques for developing custom hunting dashboards and detecting both generic and advanced attacks.

### Tools Mentioned

1. **Event Viewer**
    
    - Tool to access and view event logs on Windows.
2. **Microsoft’s Documentation**
    
    - Provides detailed information about specific event IDs.
3. **Log Parsing and Analysis Tools**
    
    - Various tools to parse and analyze log data, such as:
        - **LogParser**: Used for querying Windows event logs.
        - **Sysmon**: Extends logging capabilities of Windows.
4. **SIEM Systems**
    
    - SIEM systems like Splunk and ELK (Elasticsearch, Logstash, Kibana) are essential for centralizing and analyzing logs from multiple sources.
5. **PowerShell**
    
    - Useful for scripting and automating log analysis tasks.
6. **Third-Party Tools**
    
    - Examples include PE Sieve and API Monitor for specific attack detection tasks.
