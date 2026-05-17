# SOC Workflow (v2)

The platform now models a realistic SOC analyst loop end-to-end.

```
Raw logs -> Parse -> Detect -> Findings
                                |
                                v
                  Alerts (priority + FP estimate)
                                |
                                v
                Triage queue summary + filters
                                |
                                v
                 Cases (per-actor, classified)
                                |
                                v
                  Entity profiles (risk-scored)
                                |
                                v
              Kill-chain view + MITRE coverage
                                |
                                v
               SOC report (JSON + Markdown)
```

## Lifecycle of an alert

1. A detection rule fires against parsed events, producing a `Finding`.
2. `triage.generate_alerts_from_findings` creates an `Alert` per finding,
   normalizing severity into a priority (P1-P4) and attaching an
   actionable recommendation.
3. `false_positive.annotate_alerts_with_fp_likelihood` scores each alert
   for likely false-positive risk so analysts can de-prioritize noise.
4. `cases.create_cases_from_alerts` groups alerts by primary source IP
   and classifies the resulting case (brute force, web attack, scan,
   beacon, privilege escalation, multi-stage).
5. `entities.build_entity_profiles` aggregates events, findings, and
   alerts per IP, user, domain, and path.
6. `kill_chain.build_kill_chain_view` maps MITRE techniques to canonical
   kill-chain stages.
7. `coverage.build_detection_coverage_matrix` shows which MITRE
   techniques are covered by current rules and where the gaps are.
8. `reporting.build_soc_report` returns a single JSON payload combining
   all of the above; `build_soc_markdown_report` renders it as Markdown.

## Outputs

| Endpoint | Purpose |
| -------- | ------- |
| `/triage/sample` | Generate the triage queue for all bundled sample logs |
| `/triage/analyze` | Triage queue for analyst-supplied raw logs |
| `/cases/sample` | Cases for all bundled sample logs |
| `/cases/from-analysis` | Cases for analyst-supplied raw logs |
| `/false-positive/review` | Annotated alerts + FP summary |
| `/rules/tuning` | Rule performance + tuning recommendations + gaps |
| `/entities/sample` | Entity risk profiles for all bundled sample logs |
| `/entities/analyze` | Entity risk profiles for analyst-supplied raw logs |
| `/kill-chain/sample` | Kill-chain view for all bundled sample logs |
| `/kill-chain/analyze` | Kill-chain view for analyst-supplied raw logs |
| `/coverage/mitre` | MITRE coverage matrix + summary |
| `/report/soc-json` | Full SOC report (JSON) |
| `/report/soc-markdown` | Full SOC report (Markdown) |
