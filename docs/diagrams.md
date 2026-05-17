# Diagrams

## Request flow

```
[Analyst] -> [React UI] -- POST /analyze --> [FastAPI]
                                               |
                                               v
                                          parsers.py
                                               |
                                               v
                                          detectors.py
                                               |
                                               v
                                          mitre.py + risk.py
                                               |
                                               v
                                     summarizer.py + timeline.py
                                               |
                                               v
                                          correlation.py
                                               |
                                               v
                                          reporting.py
                                               |
                                               v
                                       IncidentReport (JSON)
                                               |
                                               v
                                          [React UI]
```

## Rule engine dispatch

```
rule.match_type
  ├── regex     -> _regex_rule
  ├── threshold -> _threshold_rule
  ├── port_scan -> _port_scan_rule
  ├── path_scan -> _path_scan_rule
  ├── dga       -> _dga_rule
  └── beacon    -> _beacon_rule
```

## Severity gradient

```
informational (blue) < low (green) < medium (yellow) < high (orange) < critical (red)
```

## v2 SOC pipeline

```
Findings -> Alerts -> Cases
                |        |
                v        v
             Entities  KillChain
                |        |
                v        v
            Coverage  RuleTuning
                |        |
                +---+----+
                    v
              SOC Report (JSON + Markdown)
```

## Kill-chain stages

```
reconnaissance -> initial_access -> execution -> persistence ->
privilege_escalation -> credential_access -> discovery ->
lateral_movement -> command_and_control -> exfiltration -> impact
```
