# False Positive Review

## Output shape

```json
{
  "likelihood": "low",
  "score": 10,
  "reasons": ["Rule R008 relies on strong evidence; FP unlikely.", "..."]
}
```

The `score` ranges from `0` (no FP risk) to `100` (almost certainly FP).

## Likelihood thresholds

| Score | Likelihood |
| ----- | ---------- |
| `>=60` | high |
| `30..59` | medium |
| `<30` | low |

## Heuristics

- Rules with strong, explicit evidence (sqlmap UA, exact `/etc/shadow`,
  threshold-based brute force) lower the FP score.
- Rules with broad evidence (404 burst, broad path scan) raise the FP
  score.
- Critical/high severity lowers FP; low/informational raises FP.
- Known scanner user-agent in any matched event lowers FP.
- Multiple supporting events lower FP; a single event raises FP.

## Endpoint

- `POST /false-positive/review` — `{log_type, raw_logs}`.

Returns annotated alerts and a summary with `low_likelihood`,
`medium_likelihood`, `high_likelihood`, and `review_recommended`.
