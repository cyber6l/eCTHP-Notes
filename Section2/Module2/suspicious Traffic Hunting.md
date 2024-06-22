 #### ARP (Address Resolution Protocol) Traffic

ARP is fundamental in network communications, operating at Layer 2 of the OSI model. It resolves IP addresses to MAC addresses through ARP Request and Reply messages, crucial for proper data transmission.

**Differentiating Normal and Suspicious Traffic**:

- **Normal ARP Traffic**: In a typical network environment, ARP broadcasts occur at a reasonable rate from both clients and servers. These transmissions involve ARP Requests and corresponding Replies (Opcode 1 and 2 respectively) to resolve IP addresses to MAC addresses.

![Screenshot 2024-06-17 222745](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/0bca275b-8419-438f-a4b2-8b18703b5367)
    
- **Suspicious ARP Traffic**: Suspicious behavior includes excessive ARP broadcasts within a short timeframe, often indicative of scanning activities like those conducted by tools such as Nmap. Additionally, instances where the same MAC address is associated with different IP addresses suggest ARP spoofing, a potential security threat.

for more [(PDF) ARP Spoofing- Analysis using Wireshark on 2 different OS LINUX and WINDOWS | Debojyoti Sengupta - Academia.edu](https://www.academia.edu/5648727/ARP_Spoofing_Analysis_using_Wireshark_on_2_different_OS_LINUX_and_WINDOWS)

#### here are the images that were referenced in the TryHackMe Wireshark Traffic Analysis challenge:
#### Normal
![Screenshot 2024-06-17 224359](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/10e5fe91-213c-4f83-b9b9-adb7bde767ea)

Proper ARP Request followed by a single ARP Reply with correct MAC address mapping
#### Suspicious
![Screenshot 2024-06-17 224605](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/537786ff-7c81-4b12-8425-562a8451c7db)

Multiple ARP Requests with incrementing IP addresses and minimal time intervals, suggesting systematic scanning or reconnaissance by malicious actors.
Or sometimes ARP Spoofing attack by looking for a MAC address being used by two different IP addresses


Identifying Suspicious Patterns:
In suspicious ARP traffic, anomalies such as frequent and rapid ARP broadcasts without corresponding Replies, or ARP Replies sent gratuitously (without prior Request), can indicate attempts to manipulate ARP cache entries (ARP poisoning) or unauthorized network scans.

Gratuitous ARP Replies:
Attackers may use gratuitous ARP replies to introduce false MAC address mappings into ARP caches, attempting to intercept network traffic or disrupt communications. They often send these replies periodically to maintain the false entries.

This proactive approach helps safeguard network integrity and data confidentiality against various ARP-related vulnerabilities.👍

--------------------------------------------------------------------------

#### ICMP (The Internet Control Message Protocol) Traffic

**(ICMP)** is primarily used for error reporting and diagnostics in network communications. It operates at the Network Layer (Layer 3) of the OSI model, which is the same layer as the Internet Protocol (IP). Unlike other protocols, ICMP does not have specific ports.

**Uses of ICMP:**

1. **Troubleshooting Network Issues:**
    
    - ICMP is commonly used for network diagnostics and troubleshooting. For example, if your device is experiencing connectivity issues, ICMP can help determine if there is a problem with the internet connection.
2. **Ping:**
    
    - The `ping` command utilizes ICMP to check the availability of a destination device on a network. When you `ping` a device, ICMP sends an echo request and waits for an echo reply. If a reply is received, the device is active and reachable.
![Screenshot 2024-06-18 143650](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/6e75779d-aa2c-4ade-9b75-fca2f77f1871)
     
3. **Traceroute:**
    
    - `Traceroute` uses ICMP to trace the path packets take to reach a destination IP address. It helps identify the various gateways (routers) the packets pass through on their journey to the target.
![Screenshot 2024-06-18 143828](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/91885733-7ef6-4ddb-9f18-5010aa0f7507)
    

**ICMP Packet Types:**

- **Echo Request and Reply:**
    - An echo request (Type 8, Code 0) is sent to test connectivity, and an echo reply (Type 0, Code 0) is returned to confirm the connection.

**Detecting Suspicious ICMP Traffic:**

1. **Abnormal Packet Frequency:**
    
    - If ICMP packets are being sent excessively, it could indicate data exfiltration, where sensitive data is being transmitted covertly.
2. **Unusual Packet Sizes:**
    
    - Typically, ICMP packets have a standard length. If you notice packets with unusually large sizes (e.g., 1000 bytes instead of the usual 100 bytes), it might be a sign of an attack, such as data exfiltration disguised as ICMP traffic.
![Screenshot 2024-06-18 144857](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/0de2453e-cfd8-43f9-b422-4a4cc100db80)
3. **Unusual ICMP Types/Codes:**
    
    - Be aware of uncommon ICMP types and codes. For example, a timestamp request (Type 13) should only occur between servers. If a normal PC sends such requests, it could indicate a reconnaissance attempt by an attacker.

**Common ICMP Attacks:**

1. **Smurf Attack:**
    
    - This is a type of DDoS attack where the attacker spoofs the victim's IP address and sends ICMP echo requests to a network's broadcast address. All devices in the network respond to the victim, overwhelming it with traffic.
<img width="535" alt="Screenshot 2024-06-18 153132" src="https://github.com/cyber6l/eCTHP-Notes/assets/131306259/5786c5a7-fadd-4338-aa96-35f1c1cf86dd">
    
	
2. **ICMP Tunneling:**
    
    - Attackers may encapsulate other types of traffic (e.g., HTTP) within ICMP packets to bypass firewalls and IDS/IPS systems. Tools like `ptunnel` can be used for this purpose. Indicators of ICMP tunneling include varying packet sizes and specific data sequences within the packets.
      ![Screenshot 2024-06-18 154315](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/6f039f05-2d79-4d85-a1da-55deda53b9b9)

    
3. **ICMP Redirect Abuse:**
    
    - An attacker can send a fake ICMP redirect message to a device, causing it to route its traffic through a malicious gateway controlled by the attacker. This can be used for man-in-the-middle attacks.
<img width="761" alt="Screenshot 2024-06-18 145600" src="https://github.com/cyber6l/eCTHP-Notes/assets/131306259/5c4aebb2-f81f-4b01-b6bd-f3e51b662bd1">

**Detection and Mitigation:**

- **Packet Analysis with Wireshark:**
    
    - Use Wireshark to capture and analyze ICMP packets. Look for anomalies such as unusual types, codes, packet sizes, and frequencies.
- **Monitoring Network Traffic:**
    
    - Regularly monitor your network traffic for spikes in ICMP traffic and other irregular patterns that might indicate malicious activity.

--------------------------------------------------------------------------
### TCP (Transmission Control Protocol) Traffic

- **Definition:**
    - TCP is a protocol responsible for controlling the transmission of data between the source and the destination.
    - It ensures that packets (data units) are delivered correctly and handles any errors that occur during transmission.
    - If an error occurs while sending a packet, TCP will send an alert to inform you that the data did not reach the destination or was lost along the way.

### How TCP Works

- **Handshake Process:**
    - Before sending any data, TCP performs a process called the handshake to ensure the connection is successfully established.
    - This process involves sending a SYN from the source, receiving a SYN-ACK from the destination, and then confirming the connection with an ACK from the source.
![Screenshot 2024-06-18 161812](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/4f345058-0572-4cc0-8092-910f7d29a455)

### Normal TCP vs. Suspicious TCP

- **Normal TCP:**
    - The connection process starts with sending a SYN, followed by a SYN-ACK response, and finally an ACK to establish the connection.
![Screenshot 2024-06-18 162502](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/4c2c46ac-ae13-4380-82ff-cadc2ba39eb7)
    
- **Suspicious TCP:**
    - Multiple SYN requests are sent without receiving an ACK response.
![Screenshot 2024-06-18 165720](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/98e2abfd-14e1-4c8d-bd71-99cb26722624)   
![Screenshot 2024-06-18 165246](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/76a3885b-50dd-4407-97fd-9a98710252e3)

    
    - This behavior is typical of tools like Nmap, which perform port scanning to detect open ports.
    - Requests are sent from a single port to multiple different ports on the destination device.
    - Requests may come from a single IP to multiple IPs, indicating network scanning behavior.
### Scenarios of Suspicious Behavior

- **Scanning:**
    - Observing repeated SYN requests without receiving ACKs indicates a scanning operation.
    - Requests sent from one port to multiple ports or from one IP to several IPs suggest network scanning.
- **SYN Flooding:**
    - Sending numerous SYN requests in a short period is known as a SYN flooding attack, a type of DDOS (Denial of Service) attack.
- **Connection Refusal:**
    - In some cases, after a SYN and SYN-ACK, an RST (Reset) is sent instead of an ACK, indicating a refusal or termination of the connection. This is typical behavior of scanning tools.
![Screenshot 2024-06-18 165903](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/3b1bdc4c-5749-41ca-b592-63d7437a8418)

![Screenshot 2024-06-18 170050](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/c49171e8-339a-4b32-ab0d-2cd6c323a505)

### Handling Suspicious Behaviors

- **Detecting and Preventing Attacks:**
    - Monitor the network to detect suspicious behaviors such as scanning or flooding.
    - Take appropriate actions like dropping, resetting, or blocking suspicious connections.
    - Stay one step ahead of attackers by identifying these behaviors early.


--------------------------------------------------------------------------
#### Dynamic Host Configuration Protocol (DHCP) Traffic

- **Definition:**
    - DHCP is a protocol responsible for dynamically assigning IP addresses to devices (hosts) on a network.
    - It operates within a LAN (Local Area Network).

**Methods for Obtaining an IP Address:**

- **Manual Assignment:**
    - A user can manually assign an IP address based on the subnet mask and the instructions provided by the network administrator.
- **Automatic Assignment (DHCP):**
    - More commonly, users obtain an IP address automatically through DHCP.
    - A DHCP server must be present on the network to distribute IP addresses. This server can be located on a firewall, router, or a dedicated DHCP server.

**DHCP Server:**

- **Functionality:**
    - The DHCP server automatically assigns IP addresses to devices on the network.
    - It operates on ports 67 and 68 and uses the UDP protocol from the transport layer.

**DHCP Process (DORA):**

- **DORA Process:**
    - **Discover:** The client sends a DHCP Discover message to find available DHCP servers.
    - **Offer:** A DHCP server responds with a DHCP Offer message, offering an IP address to the client.
    - **Request:** The client sends a DHCP Request message to the server, indicating it wants to use the offered IP address.
    - **Acknowledgement:** The server sends a DHCP Acknowledgement message to confirm the IP address assignment.

### Detailed DHCP Process:

![Screenshot 2024-06-18 182845](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/583e1f74-efa7-4d63-bc76-88625e3845c4)


1. **DHCP Discover:**
    
    - The client broadcasts a Discover message to find DHCP servers on the network.
    - This message is sent to the destination IP address 255.255.255.255 (broadcast address) and destination port 67 (DHCP server port).
2. **DHCP Offer:**
    
    - The DHCP server responds with an Offer message, containing an available IP address and other configuration information.
    - This message is sent to the client’s MAC address and uses source port 67 and destination port 68 (DHCP client port).
3. **DHCP Request:**
    
    - The client responds with a Request message, indicating it accepts the offered IP address.
    - This message also includes any other network configuration information requested by the client.
4. **DHCP Acknowledgement:**
    
    - The DHCP server sends an Acknowledgement message, confirming the IP address assignment and completing the configuration process.

#### Normal process

![Screenshot 2024-06-18 190338](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/30cc5071-1f1f-4de7-bb41-97e0b10e86b8)
  Looking at packet number 1, we see that the device didn't have an IP address and sent a broadcast message to the entire network. The IP 1.1 responded with a DHCP offer, continuing through the DORA process we explained above. This is the correct and expected behavior. 
#### 1- **DHCP Discover**
![Screenshot 2024-06-18 191511](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/f3c34450-b660-41b3-ae8b-c10edb2fc2d0)
This first frame that is sent by the client as a broadcast to all available servers
#### 2-**DHCP Offer**
![Screenshot 2024-06-22 231402](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/e88003da-070e-4c99-b953-5903aed12233)
This frame is sent by the server(s) to the client with many details subnet mask. Now, the client can choose the IP address if it gets multiple DHCP offer

#### 3-**DHCP Request**
![Screenshot 2024-06-18 192831](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/add2beb4-80cb-4644-86b4-d82c945210fb)
This frame is sent by the client to the particular server confirming the IP address. It can also request for some more details from the server

#### 4-**DHCP Acknowledgement
![Screenshot 2024-06-18 193018](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/e131267a-e7d7-4648-8093-6a1712991a80)
This is the last frame of the DORA process. It is sent by the server as an acknowledgement

After the DHCP lease time expires, the client needs to send a DHCP renewal frame to extend its IP address lease. The renewal process involves two key exchanges:

1. **DHCP Request:**
    
    - During renewal, the DHCP request frame includes the client’s current IP address in the client IP address field, as the client is attempting to renew its existing IP address.
    - This request is sent as a unicast frame directly to the DHCP server.
2. **DHCP ACK:**
    
    - The DHCP ACK frame is the server’s acknowledgment of the renewal request.
    - This ACK is sent as a broadcast frame, confirming the renewal of the client’s IP address.
![Screenshot 2024-06-18 193307](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/c9bf4abc-e081-4b1d-8aa5-b23d97e09313)

#### Suspicious process

Everything we've seen so far was the normal DHCP process. Let's see how things look in a suspicious DHCP scenario:

- An attacker might impersonate the DHCP server and set up a rogue DHCP server, convincing you it's the real DHCP server. If the attacker succeeds, they perform a man-in-the-middle attack, intercepting all your communications by posing as the legitimate DHCP server. This allows them to monitor everything you do.
    
-
![Screenshot 2024-06-18 193819](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/e44b5d01-1d09-4aa2-8c09-a0c701a272bc)

![Screenshot 2024-06-18 193847](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/c6c598aa-031d-412b-892a-745e04ec83d2)


![Screenshot 2024-06-18 193937](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/13b803ae-4995-480c-be16-e565aa4a458d)

With Wireshark of the rogue DHCP server, you'll see that when the attacker received a discover message, they sent back an offer, initiating a man-in-the-middle attack instead of the original server.

--------------------------------------------------------------------------
#### DNS (Domain Name System) Traffic

- DNS operates at the application layer (Layer 4) on port 53 using the UDP protocol from the transport layer. It resolves domain names to IP addresses. For example, when you want to visit Google, you type "google.com" in your browser. This request is sent to the DNS server, which has the IP address of every website you want to visit. The DNS protocol retrieves the IP address and directs you to it, because nothing on the internet is recognized by "google.com" as such; the DNS server understands only IP addresses but knows the IP corresponding to "google.com" and has it recorded in its server.
    
- Any new domain that appears on the internet is automatically registered in the DNS server. To visit a site, your device first sends a DNS query via the DNS protocol, and the server responds, directing you to the site you entered in the browser.

### Normal vs. Suspicious DNS Traffic:

- **Normal DNS Traffic:**
    
    - DNS queries are sent from a client to a server to resolve the address of a specific website.
    - Normal traffic operates on port 53 using UDP.
    - Each DNS query has a corresponding DNS response.
    - DNS traffic should typically flow from client to server, not from client to client.
- **Suspicious DNS Traffic:**
    
    - Suspicious activity might use the same port (53) but with TCP instead of UDP.
    - While normal DNS traffic can sometimes use TCP, if you see unexpected use of TCP, it's a cause for investigation.
    - Suspicious traffic might not reach the DNS server, indicating potential malicious activity from another device.
    - You might see numerous DNS queries without corresponding responses, or the reverse, which is abnormal and indicates suspicious behavior.

![Screenshot 2024-06-18 220957](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/d6e2bc5a-9dab-4171-89ab-29f3a8bd0070)

| Feature                  | Normal DNS Traffic                          | Suspicious DNS Traffic                                |
| ------------------------ | ------------------------------------------- | ----------------------------------------------------- |
| Protocol                 | UDP                                         | TCP                                                   |
| **Port**                 | 53                                          | 53                                                    |
| **Traffic Flow**         | Client to DNS Server                        | Client to Client or unexpected flows                  |
| **Transaction ID**       | Matches in both query and response          | Mismatch or no response to queries                    |
| **Volume of Traffic**    | Low, typically small queries and responses  | High volume, especially large data transfers          |
| **Behavior**             | Client queries server for domain resolution | Unusual patterns, such as zone transfers from clients |
| **Query/Response Ratio** | Each query has a corresponding response     | Multiple queries without responses or vice versa      |
| **Use Case**             | Resolving domain names to IP addresses      | Potential data exfiltration or unauthorized access    |
| **Zone Transfers**       | Typically server to server                  | Client attempting zone transfers                      |

I will explain some differences between them in Wireshark.

#### DNS Transaction ID 
 A 16-bit field used to uniquely identify a specific DNS transaction. It is generated by the originator of the message and is included in both the request and response messages. This ID allows the DNS client to match responses with the corresponding requests.



<img width="812" alt="Screenshot 2024-06-19 234910" src="https://github.com/cyber6l/eCTHP-Notes/assets/131306259/8bf7b2a6-add2-4fc3-849f-9b340ab3cd7a">

#### Normal DNS

<img width="818" alt="Screenshot 2024-06-19 234802" src="https://github.com/cyber6l/eCTHP-Notes/assets/131306259/bd8a7272-ab58-4b8c-8c39-8ac0efaa3767">

Here it tells you that the connection was established normally because the client device reached the server on port 53 using the UDP protocol, so the connection is valid
<img width="614" alt="Screenshot 2024-06-19 235506" src="https://github.com/cyber6l/eCTHP-Notes/assets/131306259/45eeb48b-d7c9-4b85-b45d-b8274fb65685">
Here you will find the response to the query you sent, and you will see the answer to the query you sent to the server


<img width="612" alt="Screenshot 2024-06-19 235030" src="https://github.com/cyber6l/eCTHP-Notes/assets/131306259/ec68af87-d24d-4d50-ba51-54d033fffcff">Look here as well, you will find that the DNS traffic is normal, and each DNS query has a corresponding DNS response
##### $ Everything is clear and simple in normal traffic $


#### Suspicious DNS

 *Common attack is A DNS zone transffer* 
  IN Normal : the process of replicating the DNS records from one DNS server to another. This is commonly done to ensure consistency and redundancy across DNS servers. 
  
  IN Suspicious : will find an attack happening occurs between servers and clients
  And they do this in order to pull the addresses present in the DNS servers so that they can modify or manipulate them.
  
  There are two primary types of DNS zone transfers:

Full Zone Transfer (AXFR): This type of transfer replicates the entire zone file from the master DNS server to the secondary DNS server. It is typically used when a secondary server is being set up or when there have been significant changes to the DNS records.

Incremental Zone Transfer (IXFR): This type of transfer only replicates the changes (deltas) since the last transfer, rather than the entire zone. It is more efficient and reduces the amount of data transferred over the network.


<img width="396" alt="Screenshot 2024-06-20 001747" src="https://github.com/cyber6l/eCTHP-Notes/assets/131306259/51c9ecaa-c42e-43e4-8f19-76eb532bb3a7">
We will find TCP being actively used. This is because the request sent for zone transfer aims to gather all IP addresses, resulting in large traffic volume. Therefore, TCP is used contrary to UDP.

![Screenshot 2024-06-20 002021](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/530a6d29-5cf5-4852-8ba9-dd29f463d884)

In contrast, here you'll find when it sends traffic, the size is small relative to the connection, aiming for just one device's IP. Everything seems normal, unlike TCP, which often carries large traffic, raising suspicion.

As a threat hunter, you'd scrutinize any TCP traffic. If it's between servers, that's usual. But if it's from a client to a server, that's where the concern lies.

### *DNS Tunneling*
 is used for exfiltrating data. After carrying out the initial attack and exploiting vulnerabilities, the attacker performs data exfiltration. This process is similar to what occurs frequently on the Dark Web, where the attacker possesses data that cannot be easily copied or pasted due to firewall restrictions. To circumvent this, the attacker creates tunnels or channels within DNS traffic, concealing the data within these channels and extracting it covertly.

![Screenshot 2024-06-20 002545](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/59d77969-cf4e-41e0-9a86-3fe59fc1b67a)

--------------------------------------------------------------------------

#### HTTP Traffic

HTTP (Hypertext Transfer Protocol) operates on the application layer (layer 4) and is used for browsing the web. HTTP transmits data as clear text, making it vulnerable to attacks. HTTPS (Hypertext Transfer Protocol Secure) encrypts data using an SSL certificate, ensuring secure data transmission between parties.

HTTP uses a request and reply system:

- **GET Request**: To read data from another computer.
- **POST Request**: To send data to another computer.
- **DELETE Request**: To delete data on another computer.

Each request and reply has a status code that indicates the server's response :
![Screenshot 2024-06-20 111431](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/c96d627b-7214-4bfc-81c7-27f598662dcd)
You will find that some of the codes sent by the destination indicate its status. For example, if you open your browser and type in google.com and the Google page appears, it means you sent a GET request to Google. The server received it and replied with a status code 200, meaning it approved your request to browse Google and opened the page for you. Similarly, every request has a specific reply with its status code describing a particular state. If you are adding a post or writing a comment on X , you will receive a status code 201 from the server.

| **Aspect**                | **Normal HTTP Traffic**                         | **Suspicious HTTP Traffic**                                            |
| ------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------- |
| **Request Frequency**     | Regular patterns                                | Unusually high or burst requests                                       |
| **Source IP Address**     | Known, trusted IPs                              | Unknown, blacklisted, spoofed IPs                                      |
| **Destination URL**       | Legitimate URLs                                 | Unusual domains, typos, obfuscation                                    |
| Ports                     | Port 80, TCP Port 8080, TCP (used as alternate) | Excessive or unusual methods                                           |
| **Payload Content**       | Plaintext traffic                               | Malicious content if If the traffic is encrypted (e.g., SQL injection) |
| **FQDN**                  | typically web server                            | The server will point to an IP address instead of FQDN format          |
| **Response Status Codes** | Standard codes (200, 301, 404)                  | High error codes (401, 403, 500)                                       |
| **Traffic Volume**        | Normal volume                                   | Sudden traffic spikes                                                  |

In HTTP, when you send an HTTP request from your device to a server, it goes to port 80 on the server by default. If you're running an HTTP server (like a web server), it listens for requests directly on port 80. However, if you're running a HTTP Proxy Server, it acts as an intermediary between your device and the internet. It receives HTTP requests from your device and forwards them to other servers on the internet. In this case, the proxy server might use ports like 8080 or 8088 instead of the standard port 80 for various purposes such as access control or filtering 
##### (FQDN) 

The term "Fully Qualified Domain Name" (FQDN) refers to a site that has a complete domain name, like google.com. However, if you come across a site referenced only by an IP address such as 192.168.1.1, I would advise caution. It lacks a proper FQDN, which could indicate a suspicious site. While it's possible for a site to be legitimate using just an IP address, as a threat hunter, encountering this should raise concern and prompt further investigation to ensure the safety of the traffic.


#### Normal HTTP

- 1- **TCP Three-Way Handshake**:
    
    - **SYN**: The client sends a SYN (synchronize) packet to the server to initiate a connection.
    - **SYN-ACK**: The server responds with a SYN-ACK (synchronize-acknowledge) packet to acknowledge the client’s request and synchronize the connection.
    - **ACK**: The client sends an ACK (acknowledge) packet back to the server, completing the handshake.
- **Initiating HTTP Traffic**:
    
    - Once the TCP connection is established via the three-way handshake, HTTP traffic can begin. This is typically seen in packet analysis, such as with Wireshark, where the sequence of packets can be examined.

The second indication you'll find is that the source device is connecting to the destination port 80

**I can't share image from slied INE but , I explain to you in below **

Remember the tips regarding normal HTTP traffic:
• Typically port 80 
• Cleartext web-based traffic 
• Hosts are accessed using FQDNs instead of IP addresses
##### Example

GET /index.html HTTP/1.1
Host: www.example.com

1. - The server then responds with an HTTP 200 OK status code, indicating that the request has been successfully processed and the requested page will be sent.

Here is a detailed step-by-step process :

1. **Establishing TCP Connection**:
    
    - Client: Sends SYN to Server.
    - Server: Sends SYN-ACK to Client.
    - Client: Sends ACK to Server.
2. **Starting HTTP Communication**:
    
    - Client: Sends an HTTP GET request.
    - Server: Responds with HTTP 200 OK, along with the requested resource.

### Packet in Wireshark display like this for Example :

- **Packet 1**: Client to Server – SYN
- **Packet 2**: Server to Client – SYN-ACK
- **Packet 3**: Client to Server – ACK
- **Packet 7**: Client to Server – HTTP GET /index.html
- **Packet 8**: Server to Client – HTTP 200 OK

#### Suspicious HTTP


1. **Unusual Traffic Patterns**:
    
    - Sudden spikes in HTTP requests.
    - Repetitive requests to the same resource.
2. **Unusual Request Characteristics**:
    
    - Uncommon or suspicious User-Agent strings.
    - URLs with unusual parameters or encoded characters.
    - Misuse of HTTP methods (e.g., unexpected DELETE or PUT requests).
3. **Abnormal Response Codes**:
    
    - High rates of 4xx/5xx errors.
    - Unexpected successful responses (2xx codes).
4. **Header Anomalies**:
    
    - Missing or extra headers.
    - Inconsistent header values.
5. **Suspicious Payloads**:
    
    - Binary data in text-based requests.
    - Obfuscated or excessively encoded data.
6. **Unusual Source IPs**:
    
    - Requests from unexpected geographical locations.
    - Traffic from known malicious IPs.

### Example of Suspicious HTTP Activity

SQL Injection Attempt

`GET /index.php?id=1' OR '1'='1 HTTP/1.1 Host: example.com User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)`

- **Indicator**: Unusual URL parameter with SQL injection payload.
![Screenshot 2024-06-22 212911](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/126940fd-bdd3-45d4-9b66-8281d221c660)
![Screenshot 2024-06-22 213032](https://github.com/cyber6l/eCTHP-Notes/assets/131306259/9b323fb0-09df-4ab7-a771-b4e757c781a1)

#### HTTPS Traffic

- **HTTPS** operates at Layer 7 (Application Layer) and is the secure version of HTTP.
- HTTPS is considered secure because it uses the SSL (Secure Socket Layer) protocol.
- HTTPS establishes a connection using a handshake process, similar to TCP, but more complex. SSL is responsible for this process.
- The client and server must agree on the same SSL version before the connection can be established.
- They must also agree on the cryptographic algorithm before the connection.
- SSL ensures secure sessions by managing encryption keys between the client and the server.
- Authentication between the client and the server must occur before the connection.
- Both parties must agree on a public encryption key to establish the connection.

| **Aspect**                | **Normal HTTPS Traffic**                            | **Suspicious HTTPS Traffic**                                             |
| ------------------------- | --------------------------------------------------- | ------------------------------------------------------------------------ |
| **Request Frequency**     | Regular, consistent patterns                        | Unusually high volume or burst requests                                  |
| **Source IP Address**     | Known, trusted IPs                                  | Unknown, blacklisted, or spoofed IPs                                     |
| **Destination URL**       | Legitimate, expected URLs                           | Unusual domains, typosquatting, or obfuscated URLs                       |
| **Ports**                 | Standard ports  (443 for HTTPS) (8443)              | Use of non-standard or unexpected ports                                  |
| **Payload Content**       | Encrypted, expected content                         | Malicious content, even if encrypted (e.g., backdoors, malware payloads) |
| **FQDN**                  | Resolves to legitimate Fully Qualified Domain Names | May resolve directly to IP addresses instead of domain names             |
| **Response Status Codes** | Standard codes (200, 301, 404)                      | High frequency of error codes (401, 403, 500)                            |
| **Traffic Volume**        | Consistent with normal usage patterns               | Sudden, unexpected spikes in traffic volume                              |
#### **Normal HTTPS 

#### Secure Form Submission on a Website

`POST /submit-form HTTP/1.1 Host: www.example.com User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Content-Type: application/x-www-form-urlencoded Content-Length: 89 Connection: keep-alive  name=John+Doe&email=johndoe%40example.com&message=Hello%2C+this+is+a+test+message  HTTP/1.1 200 OK Content-Type: text/html; charset=UTF-8 Content-Length: 512`

- **Request Frequency**: Normal submission frequency for form submissions.
- **Source IP Address**: Known IP addresses from a user's ISP.
- **Destination URL**: Legitimate form submission URL on the website.
- **Ports**: Standard HTTPS port 443.
- **Payload Content**: Encrypted form data.
- **FQDN**: Resolves to [www.example.com](http://www.example.com).
- **Response Status Codes**: Standard code 200 OK.
- **Traffic Volume**: Consistent with normal form submission activity.


#### Suspicious HTTPS

#### DDoS Attack with Burst Requests


`GET / HTTP/1.1 Host: www.example.com User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8 Accept-Encoding: gzip, deflate, br Accept-Language: en-US,en;q=0.5 Connection: keep-alive  HTTP/1.1 403 Forbidden Content-Type: text/html; charset=UTF-8 Content-Length: 512`

- **Request Frequency**: Extremely high volume of requests in a short period.
- **Source IP Address**: Spoofed or unknown IP addresses, often geographically dispersed.
- **Destination URL**: Legitimate homepage URL.
- **Ports**: Standard HTTPS port 443.
- **Payload Content**: Encrypted, but excessive volume.
- **FQDN**: Resolves to [www.example.com](http://www.example.com).
- **Response Status Codes**: High frequency of 403 Forbidden errors.
- **Traffic Volume**: Massive spikes in traffic volume indicative of a DDoS attack.


#### Unknown Traffic

1. **Traffic Filtering**: Focus on port 443, expected to be encrypted. However, the observed traffic was not encrypted, indicating it was not SSL traffic.
    
2. **Protocol Identification**: The traffic involved the AOL Instant Messenger (AIM) protocol, specifically using OFT2 for file transfer.
    
3. **Wireshark Usage**:
    
    - **Before Decoding**: Traffic appeared normal without specific protocol dissection.
    - **Decode As Feature**: Right-click on the packet in Wireshark, use "Decode As" to specify the AIM protocol.
    - **After Decoding**: Detailed information about the OSCAR (OFT2) protocol was revealed.
4. **Key Tools**: Wireshark and its protocol dissectors are essential for decoding and analyzing unknown traffic.
    
---
