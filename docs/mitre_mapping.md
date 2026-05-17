# MITRE ATT&CK Mapping

The project uses a local simplified mapping in
`data/mitre/mitre_mapping.json`. No external fetch is performed.

| ID | Name | Tactic |
| -- | ---- | ------ |
| T1110 | Brute Force | Credential Access |
| T1059 | Command and Scripting Interpreter | Execution |
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1087 | Account Discovery | Discovery |
| T1046 | Network Service Discovery | Discovery |
| T1021 | Remote Services | Lateral Movement |
| T1071 | Application Layer Protocol | Command and Control |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1003 | OS Credential Dumping | Credential Access |
| T1055 | Process Injection | Defense Evasion |
| T1566 | Phishing | Initial Access |
| T1595 | Active Scanning | Reconnaissance |

## Rule -> technique map (excerpt)

| Rule | Techniques |
| ---- | ---------- |
| R001 SSH brute force | T1110 |
| R002 Invalid user login | T1110, T1087 |
| R003 Sudo sensitive file access | T1003 |
| R004 SQL injection | T1190 |
| R005 XSS | T1190 |
| R006 Directory traversal | T1190 |
| R007 Admin panel probing | T1190, T1595 |
| R008 Scanner UA | T1595, T1190 |
| R010 Port scan | T1046, T1595 |
| R012 Suspicious outbound 4444 | T1071, T1105 |
| R013 DGA-like domain | T1071 |
| R015 C2 beacon | T1071, T1105 |
| R018 Credential dumping hint | T1003 |
| R019 Command execution probe | T1059, T1190 |

## Disclosure

Descriptions are simplified for educational use. They are not a substitute
for the canonical MITRE ATT&CK reference.
