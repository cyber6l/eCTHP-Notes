#### MITRE ATT&CK 
#### Overview

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a detailed framework that models cyber adversary behavior, covering different attack phases and targeted platforms. It's widely used for understanding, detecting, and mitigating cyber threats.
 
- **Tactics**: High-level adversary goals.
- **Techniques**: Methods used to achieve tactics.
- **Procedures**: Detailed steps for executing techniques.

The framework is structured as a matrix, with columns representing tactics and cells representing techniques. Each technique includes:

- Detailed explanations
- Real-world examples
- Mitigation strategies
- Detection suggestions
- Metadata

#### Data Collection

1. **Purpose-Driven Collection**:
    
    - Collect data with a clear objective based on a hypothesis.
    - Focus on relevant host and network data.
2. **Exporting Data**:
    
    - **Push**: Automatic forwarding by host agents.
    - **Pull**: Remote collection during connections.
    - **Combination**: Using both methods.
3. **Assessment of Data Collection**:
    
    - Ensure availability of needed data, environmental coverage, historical data search capabilities, and data quality.

#### Data Governance

1. **Definition**:
    
    - Management of data availability, usability, integrity, and security for consistency and trustworthiness.
2. **Data Quality Aspects**:
    
    - Completeness, consistency, and timeliness of data.
3. **Identifying Anomalies**:
    
    - Baseline normal activities to detect anomalies.

#### Data Analysis

1. **Tools**:
    
    - SIEM systems like ELK/HELK, Splunk, and Graylog.
2. **Analysis Techniques**:
    
    - **Searching**: Finding answers and identifying anomalies.
    - **Aggregation**: Grouping data to identify patterns.
3. **Utilizing Multiple Data Sources**:
    
    - Switch data sources when initial results are incomplete.

### Hunting Hypothesis and Methodology

#### 5-Step Process for Hunting

1. **Pick a Tactic and Technique**:
    
    - Use MITRE ATT&CK to select an attack technique.
2. **Identify Associated Procedure(s)**:
    
    - Research procedures, prerequisites, and outcomes.
3. **Perform an Attack Simulation**:
    
    - Simulate the attack in a controlled environment to understand generated data.
4. **Identify Evidence to Collect**:
    
    - Look for artifacts and deviations from baselines.
5. **Set Scope**:
    
    - Define hunt duration and data sources, considering limitations.

### Hunting Metrics

#### Considerations for Defining Metrics

1. **Activity Detection**:
    
    - Success isn’t only finding malicious activity but ensuring thorough coverage.
2. **Simulated Activity**:
    
    - Avoid simulations in production; coordinate with penetration testing.
3. **Control Factors**:
    
    - Frequency of hunts, technique and procedure coverage, network coverage, and historic logging capability.
---

