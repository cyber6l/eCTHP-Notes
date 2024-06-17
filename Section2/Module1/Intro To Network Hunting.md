بالبدايه لازم تعرف تفاصيل هيكليه ال Layering عن Protocols تستعمل مثل TCP-IP , OSI
![Pasted image 20240615222634](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/55e70cea-905c-46df-bf0d-0a259ba44142)
![Pasted image 20240615222651](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/66a718f6-2a00-458b-92f3-7d577852b881)
![Pasted image 20240615222714](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/36bf6354-06e3-4a84-af67-0f24cbb14632)
![Pasted image 20240615222729](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/f8b90b27-e30e-45bb-bf79-023db3a99be5)
![Pasted image 20240615222745](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/e56f5126-04db-403b-86df-fc677160f9ea)
![Pasted image 20240615222805](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/8c790531-d533-41a8-b984-08484356d258)

### Encapsulation Process

- During encapsulation, each protocol adds a header to the packet, treating it as a payload.
- This process is reversed at the destination host.

### Internet Protocol (IP)

- IP operates at the Internet layer of the TCP/IP suite.
- It delivers datagrams (IP packets) using IP addresses to identify hosts.

### Routing

- Routers connect different networks and forward IP datagrams based on routing protocols.
- They inspect destination addresses and use routing tables to map IP addresses to interfaces.
- The routing table includes a default address (0.0.0.0) for unknown destinations.
- Routing protocols assign metrics to links for path selection, considering bandwidth and congestion.

### Switching

- Switches use MAC addresses and maintain a forwarding table (Content Addressable Memory or CAM table).
- They forward packets based on MAC addresses.

### Protocol Familiarity

- Understanding ARP, TCP, UDP, DNS, and other protocols is essential for packet analysis.
- Knowing how these protocols communicate and their differences is crucial.

### ARP (Address Resolution Protocol)

- When host A wants to communicate with host B but only knows B's IP address:
    1. A sends an ARP request with B's IP and FF:FF:FF:FF:FF
        
        as the destination MAC address.
    2. All hosts on the network receive the request.
    3. B responds with an ARP reply, providing its MAC address to A.

#### TCP uses a 3-way handshake to establish communication between two hosts because the protocol is connection orientated
![[Pasted image 20240615225933.png]]

#### TCP header
![[Pasted image 20240615230120.png]]

#### UDP don't uses a 3-way handshake because the protocol is connectionless

#### UDP header
![[Pasted image 20240615230323.png]]

Some important ports you should know which port they typically communicate on 
[Common Ports Cheat Sheet: The Ultimate List (stationx.net)](https://www.stationx.net/common-ports-cheat-sheet/)

#### Packet Capture and Analysis

- **PCAP Format**: Standard format for packet captures; tools export and import PCAP files.
- **Scenario**: Common situations for network analysis include detecting unusual traffic, alerted by the Network Team.

#### Role of a Threat Hunter

- **Responsibilities**: Analyzing PCAP files provided by Network Team or conducting live captures.
- **Limitations**: Not expected to manually monitor or analyze terabytes of traffic daily.

#### Defense-in-Depth and Monitoring

- **Security Appliances**: Appliances and configured rulesets alert for suspicious activities; Continuous Threat Intelligence (CTI) updates rulesets.

#### Occasional Deep Dives

- **Need for Analysis**: Instances like IDS/IPS downtime may require reviewing packet captures for missed malicious activities.

#### Network Understanding

- **Network Familiarity**: Essential for effective threat hunting; knowledge of infrastructure, IP schemes, network rules, and egress points.

#### Platform and Tool Familiarity

- **Operating Systems**: IT Security uses Windows; Red Teamers use Linux; Threat Hunters (Purple Teamers) should be proficient in both.

#### Network Traffic Capture Considerations

- **Live Capture**: Key considerations include ensuring correct traffic capture, sufficient computing power, and disk space.
- **Switch Considerations**: Use of mirrored ports (SPAN ports) for capturing traffic; alternatives include network taps, MAC flooding, or ARP spoofing if SPAN ports are unavailable.

#### Tools for Packet Analysis

- **libpcap**: Unix C library for packet sniffing and analysis; basis for tools like Wireshark and tcpdump.
- **WinPcap**: Equivalent library for Windows systems, supporting tools like Wireshark.

### Wireshark

- **Wireshark**: Network sniffer and protocol analyzer; supports packet analysis across different operating systems.
- **Features**: Capable of dissecting and examining packets, traffic streams, and connections.

### Dumpcap
is a command-line packet capture tool bundled with Wireshark, designed for capturing network traffic on Unix-based systems. It lacks a GUI but offers robust capabilities for automated packet capture and filtering, saving data in the pcap format.

### Tcpdump 
is another command-line packet sniffer for Unix-based systems like Linux, FreeBSD, and macOS. It intercepts and displays TCP/IP packets in real-time, supports extensive filtering, and saves captured data for analysis. It's essential for network monitoring, troubleshooting, and security analysis tasks.

### Berkley Packet Filter (BPF) 
is a filtering mechanism used by tools like Tcpdump and Wireshark to capture specific network traffic based on defined criteria. BPF filters allow users to specify precisely which packets should be captured or analyzed, enhancing efficiency and focusing on relevant data.

