
What is APT ?

	Skilled hackers sneak into a system, steal data in small bits for a long time, all to stay hidden.


What is TTP ?

### Tactics

Tactics explain the "why" behind actions, involving the strategic arrangement of forces to achieve a goal.

### Techniques

Techniques describe "how" actions are performed, using specific methods to accomplish tactical objectives.

### Procedures

Procedures are the detailed steps that implement each technique, outlining the exact process for tasks.


*explain how adversaries infiltrate and navigate a network to accomplish their objectives. Understanding TTPs helps in identifying the adversary in future attacks by creating Indicators of Compromise (IOCs).*

What is IOCs ?

	IOCs (Indicators of Compromise) are artifacts collected from active or previous intrusions used to identify a specific adversary. These artifacts include MD5 hashes, IP addresses, executable names, and more.

APT 1 uses two custom utilities to steal emails from their victims:

- **GETMAIL**: Malware that extracts email messages and attachments from Outlook PST files.
- **MAPIGET**: Malware that extracts email messages and attachments from an Exchange server.


#### The Pyramid of Pain classifies indicators of compromise (IOCs) and adversary tactics based on their effectiveness and difficulty of detection:

- **Hash Values:** Used to verify the authenticity of files but easily changed, hence less reliable.
- **IP Addresses:** Easily masked through anonymity channels, but blacklisting can disrupt adversaries.
- **Domain Names:** Dynamic and easily changed; adversaries exploit various techniques for evasion. By using : 
![Screenshot 2024-06-07 150605](https://github.com/cyber6l/eCTHP/assets/131306259/01c033cd-6fdc-41fe-b316-86ec66f90db3)
 IDN Homograph Attack 
![Screenshot 2024-06-07 151008](https://github.com/cyber6l/eCTHP/assets/131306259/2fe1dc9d-8cb9-4efe-aad4-5043b98886e8)
  Punycode

- **Network/Host Artifacts:** Clues left by adversaries; detecting specific tools forces them to adapt, increasing their workload.
- **TTPs (Tactics, Techniques, and Procedures):** Represent adversaries' methods; retraining adversaries is costly and challenging, but effective in increasing their operational costs.

![Screenshot 2024-06-07 144646](https://github.com/cyber6l/eCTHP/assets/131306259/71d322d6-01c9-4053-b32c-2313199aafc3)


#### The Cyber Kill Chain: outlines the stages of a cyber attack. In both realms, it denotes the step-by-step progression of an offensive operation.

1- Recon: Gathering information on the target.
2- Weaponize: Developing and preparing the attack.
3- Deliver: Transporting the malicious payload to the target.
4- Exploit: Taking advantage of vulnerabilities to infiltrate.
5- Install: Implanting the malware on the target system.
5- C&C (Command & Control): Establishing control over the compromised system.
6- Action: Executing the intended malicious activities on the target.


#### Threat intelligence can be categorized into three types: 
- Strategic intelligence: This type assists senior management in making informed decisions about security budget and strategies by addressing questions about ==who== the adversary is, ==why== they are targeting you, and ==where== they have attacked previously.
    
- Tactical intelligence: It deals with the adversary's Tactics, Techniques, and Procedures (TTPs), aiming to identify their patterns of attacks using models like the Cyber Kill Chain and Diamond Models. ==(What and When)==
    
- Operational intelligence: This focuses on the actual indicators, known as IOCs, addressing ==how== the adversary conducts their attacks.

####  Threat Hunting Mindset: Digital Forensics
   This type of threat hunter focuses on host, network, and memory forensics when hunting for unknown threats. Data sources may include:

- Network, VPN, and Firewall logs
- Disk/Share Access
- Disk Forensic artifacts and advanced system logging
- Memory Forensic artifacts
- Reputation-based intelligence
- Passive DNS

While they still use threat intelligence, they go beyond it by analyzing digital artifacts proactively to detect threats. This is human-based detection and doesn't wait for automated alerts.

**Key Components of a Good Hunter:**

- Knowledge of available data sources/logs
- Understanding a broad variety of attacks
- Knowing what attacks can be detected in different data sources/logs
- Ability to find reliable sources about new attack techniques

A good hunter should identify variations of attacks, not just known examples.

**Hunting Methods:**

1. **Attack-Based Hunting:** Searches for specific attacks in the environment by asking questions like, "Did pass the hash happen in my network?"
    
2. **Analytics-Based Hunting:** Examines data for anomalies, asking, "Does anything in this data look malicious?" Examples include unexpected encryption or a receptionist accessing HR data.
    

**Hunting Periods:**

1. **Point in Time:** Detects what's happening at a specific moment but may miss short-lived data.
2. **Real Time:** Detects ongoing activity with data sent to SIEM.
3. **Historic:** Uses logs to identify past activities, requiring pre-configured logging.
