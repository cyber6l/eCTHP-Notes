#### MITRE ATT&CK 

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a comprehensive, curated knowledge base and model for cyber adversary behavior. It reflects various phases of an adversary’s attack lifecycle and the platforms they are known to target. ATT&CK is used widely for understanding, detecting, and mitigating cyber threats. It serves as a framework for:

Tactics: The high-level objectives or goals of an adversary during an attack.
Techniques: The specific methods adversaries use to achieve their tactics.
Procedures: The detailed, actionable steps adversaries take to execute techniques.

The MITRE ATT&CK framework is structured as a matrix, where each column represents a tactic, and each cell (box) within the columns represents a technique. There are over 200 techniques, each documented with:

- **Explanations**: Detailed descriptions of the technique.
- **Procedure Examples**: Real-world instances often linked to threat reports.
- **Mitigation Strategies**: Suggested measures to prevent or lessen the impact of the technique.
- **Detection Suggestions**: Methods to identify the use of the technique.
- **Metadata**: Additional information such as system requirements and permissions needed.
https://attack.mitre.org/techniques/enterprise/

#### Data Collection

1. **Purpose-Driven Collection:**
    
    - **Objective:** Collect data with a clear purpose based on a hypothesis.
    - **Avoid:** Collecting excessive, irrelevant logs.
    - **Primary Data Types:** Host data and network data.
2. **Exporting Data:**
    
    - **Methods:**
        - **Push:** Agents on hosts automatically forward log data.
        - **Pull:** Data is collected remotely during connections.
        - **Combination:** Utilizing both push and pull methods.
3. **Assessment of Data Collection:**
    
    - **Key Considerations:**
        - Availability of needed data for hunting.
        - Environmental coverage during hunts.
        - Historical data search capabilities.
        - Data quality and consistency across sources.

---

#### Data Governance

1. **Definition:**
    
    - Management of data availability, usability, integrity, and security.
    - Ensures data consistency and trustworthiness.
2. **Data Quality Aspects:**
    
    - **Completeness:** Availability of all required data.
    - **Consistency:** Standard naming conventions across sources.
    - **Timeliness:** Accurate timestamps reflecting event creation times.
3. **Identifying Anomalies:**
    
    - **Understanding Normal:** Baselining regular activities to define "normal" behavior.
    - **Regular Activities Include:**
        - Running processes.
        - User logons (details on where, when, and type).
        - Network connections.
        - Services and scheduled tasks.
        - Authorized software executions.

---

#### Data Analysis

1. **Tools:**
    
    - SIEM systems such as ELK/HELK, Splunk, Graylog.
2. **Analysis Techniques:**
    
    - **Searching:**
        - Finding answers to questions.
        - Modifying searches to refine results.
        - Identifying anomalies.
    - **Aggregation:**
        - Grouping data to identify patterns and outliers.
        - Performing statistical analysis (count, sum, average, frequency).
3. **Search and Aggregation:**
    
    - **Searching Queries:** Use Boolean operators, comparison operators, and wildcards.
    - **Aggregation Examples:**
        - Counting occurrences of process names.
        - Displaying details of executed commands (who, what, where, how often).
4. **Utilizing Multiple Data Sources:**
    
    - **When Results Are Incomplete:**
        - Switch to other data sources.
        - Example: Correlate suspicious IP connections with PCAP/NetFlow data to verify events.

### Hunting Hypothesis and Methodology

---

#### Introduction

Every hunt begins with a hypothesis, focusing on a specific behavior to hunt for, understanding the attack technique, and identifying the necessary data sources for detection. This process follows a 5-step methodology.

---

#### 5-Step Process for Hunting

1. **Pick a Tactic and Technique**
    
    - Utilize the MITRE ATT&CK framework to select an attack technique.
    - Example: Technique T1502 - Parent PID Spoofing under "Privilege Escalation."
2. **Identify Associated Procedure(s)**
    
    - Review procedures associated with the chosen technique.
    - Perform additional research through reports and blog posts to understand the procedures, prerequisites, requirements, and outcomes.
3. **Perform an Attack Simulation**
    
    - Replicate the procedure in a controlled environment to observe the generated data and logs.
    - This step helps identify behaviors for building future detections.
4. **Identify Evidence to Collect**
    
    - Investigate areas that may contain artifacts of interest (disk, memory, network traffic, registry).
    - Look for deviations from baselines, attempts to appear normal, unexpected encryption, and odd frequencies of occurrences.
5. **Set Scope**
    
    - Define the hunt’s duration and the data sources to be collected.
    - Consider limitations such as network bandwidth and analysis capabilities.
    - Outline assumptions and limitations impacting future hunts.

---

#### Step Details

1. **Pick a Tactic and Technique**
    
    - Example: Parent PID Spoofing involves adversaries spoofing the parent process identifier to evade defenses or elevate privileges.
2. **Identify Associated Procedure(s)**
    
    - Procedures may involve prerequisites like a compromised system and requirements such as process paths and fake parent process names.
    - Outcome: Creation of new processes.
3. **Perform an Attack Simulation**
    
    - Replicate the attack to understand what data is generated.
    - Identify behaviors that can be used for future detection.
4. **Identify Evidence to Collect**
    
    - Look for signs such as deviations from normal activity and attempts to blend in.
    - Identify false positives unique to your environment and filter them out.
5. **Set Scope**
    
    - Define the hunt’s duration and data collection sources.
    - Example scope: 1 week duration, collecting Event Tracing for Windows (ETW) logs from all Windows devices.
    - Document any unsolved activities for future reference.

---
### Hunting Metrics

---

#### Purpose and Definition

Hunting metrics are essential for tracking the progress of hunting expeditions and reporting back to management. Effective metrics should reflect the thoroughness and effectiveness of the hunt, rather than merely the discovery of malicious activity.

---

#### Considerations for Defining Metrics

1. **Activity Detection**
    
    - Finding malicious activity is not the sole indicator of a successful hunt; the absence of findings could simply mean there's nothing malicious present.
2. **Simulated Activity**
    
    - Avoid simulating malicious activity in production environments.
    - Coordinate with the penetration testing team to evaluate detection capabilities.
3. **Control Factors**
    
    - Metrics should highlight the aspects hunters can control:
        - **Frequency of Hunts:** How regularly hunts are conducted.
        - **Technique Coverage:** Extent of coverage of MITRE ATT&CK techniques.
        - **Procedure Coverage:** Coverage of procedures related to specific groups relevant to the business.
        - **Network Coverage:** Scope of network areas covered during hunts.
        - **Historic Logging Capability:** Ability to access and analyze historical data to facilitate hunts.

---

