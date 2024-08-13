
### **1. Get Volatility 2**

#### **Option 1: Clone from GitHub**

`git clone https://github.com/volatilityfoundation/volatility.git`
#### **Option 2: Zip Download**

Alternatively, grab a zip from the [Volatility 2 GitHub page](https://github.com/volatilityfoundation/volatility/releases).

### **2. Set Up**

After retrieval, go to the Volatility 2 directory:

`cd volatility`
### **3. Execute Volatility 2**

Run the tool with:

`python2 vol.py -h`

This will display help details, showcasing available commands.

### **4. Popular Plugins**

Volatility 2 offers a variety of plugins to explore memory dumps. Here are some frequently used ones:

https://blog.onfvp.com/post/volatility-cheatsheet/

#### **pslist**

- **Purpose**: Show all active tasks.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 pslist`
    

#### **pstree**

- **Purpose**: Depict tasks hierarchically, highlighting task links.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 pstree`
    

#### **pssca**

- **Purpose**: Locate task structures, i.e., active, covert, or halted.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 pssca`
    

#### **dlllist**

- **Purpose**: Show all DLLs tied to each task.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 dlllist`
    

#### **hadles**

- **Purpose**: Show all active hadles, such as files, registries, a host of items.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 hadles`
    

#### **cmdlie**

- **Purpose**: Reveal CLI flags tied to tasks.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 cmdlie`
    

#### **filesca**

- **Purpose**: Locate file entities within the memory state.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 filesca`
    


#### **socksca**

- **Purpose**: Locate socked setups i the memory state.
- **Use**:
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 socksca`
    

#### **hivelist**

- **Purpose**: Reveal registry entities i the memory state.
- **Use**:
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 hivelist`
    

#### **hashdup**

- **Purpose**: Retrieve secret hashes from the state, typically via the SAM base.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 hashdup`
    

#### **shellbags**

- **Purpose**: Extract & study ShellBag data, which tracks folder setup history & activity.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 shellbags`
    

#### **ftparser**

- **Purpose**: Study the Master File Table (MFT) for file system activity.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 ftparser`
    

#### **vaddump**

- **Purpose**: Retrieve the virtual address space of a task.
- **Use**:
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 vaddump -p <process_id>`
    

#### **procdump**

- **Purpose**: Retrieve the executable image of a task.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 procdump -p <process_id> -D <output_directory>`
    

#### **iehistory**

- **Purpose**: Retrieve history from the IE browser.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 iehistory`
    

#### **chromehistory**

- **Purpose**: Retrieve history from the Chrome browser.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 chromehistory`
    

#### **alwarecmd**

- **Purpose**: Look for regular malware C&C servers.
- **Use**:
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 alwarecmd`
    

#### **yarasca**

- **Purpose**: Look for specific code patterns or malware using YARA rules.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 yarasca -y <yara_rule>`
    

#### **clipoard**

- **Purpose**: Extract clipboard data from the memory state.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 clipoard`
    

#### **tielines**

- **Purpose**: Build a chronological record of events from various memory data sources.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 tielies`
    

#### **autoruis**

- **Purpose**: List auto-launching tasks by exploring various registries & startup directories.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 autoruis`
    

#### **ssdt**

- **Purpose**: Study the System Service Descriptor Table (SSDT) for possible threats.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 ssdt`
    

#### **devicetree**

- **Purpose**: Show the device tree of drivers i the memory state.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 devicetree`
    

#### **odsca**

- **Purpose**: Detect loaded kernel odules.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 odsca`
    

#### **alfind**

- **Purpose**: Detect potential covert code or injected processes i the memory state.
- **Use**:
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 alfind`
    
    - **-D**: Dumps detected suspicious memory regions.
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 alfind -D <output_directory>`
    
    - **-p**: Searches withi a specific task, usig PID.
    
    
    `python2 vol.py -f memory.dmp --profile=Win7SP1x64 alfind -p 1234`