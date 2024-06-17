بالبدايه لازم تعرف تفاصيل هيكليه ال Layering عن Protocols تستعمل مثل TCP-IP , OSI

![Pasted image 20240615222634](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/873f5308-16d4-4720-bfff-86e430203fdb)
![Pasted image 20240615222651](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/fb1b8f1f-e2d0-45cb-85dd-ccf6cce7cd78)
![Pasted image 20240615222714](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/bab84a47-d287-4e42-b88c-99b8976563db)
![Pasted image 20240615222729](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/36ef310c-50bf-41c6-aafb-a142b2b38391)
![Pasted image 20240615222745](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/cff6ceec-0e42-49c1-9e98-81d2ad586268)
![Pasted image 20240615222805](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/30e886e9-85e1-4d0a-bed6-1f946ee2f24c)


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
![Pasted image 20240615225933](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/8439dd0a-b1ef-4698-93c4-da408b069397)

#### TCP header
![Pasted image 20240615230120](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/cd9fa9b5-525c-4743-9a0e-ea178bf8e39f)

#### UDP don't uses a 3-way handshake because the protocol is connectionless

#### UDP header
![Pasted image 20240615230323](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/dec340b8-7ff4-4343-9290-11708408783e)

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

