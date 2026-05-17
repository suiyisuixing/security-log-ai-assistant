import React, { useEffect, useState } from 'react'
import { api } from './api.js'

function Badge({ value }) {
  const sev = (value || 'informational').toLowerCase()
  return <span className={`badge ${sev}`}>{sev}</span>
}

function BackendStatusCard() {
  const [status, setStatus] = useState('checking')
  const [info, setInfo] = useState(null)
  useEffect(() => {
    api.health()
      .then(() => api.root().then((data) => { setInfo(data); setStatus('ok') }))
      .catch(() => setStatus('down'))
  }, [])
  return (
    <div className="card">
      <h2>Backend Status</h2>
      {status === 'checking' && <span className="muted">Checking backend...</span>}
      {status === 'ok' && (
        <div>
          <span className="status-ok">Online</span>
          {info && <div className="muted">version {info.version}</div>}
        </div>
      )}
      {status === 'down' && (
        <span className="status-bad">Backend not reachable on http://127.0.0.1:8000</span>
      )}
    </div>
  )
}

function DisclosureCard() {
  return (
    <div className="card">
      <h2>Development Note</h2>
      <div className="notice">
        This project was developed as an AI-assisted learning and engineering project.
        The architecture, detection scenarios, testing goals, validation process, and
        final review were directed by the author. AI tools were used for planning,
        code review, documentation support, and debugging guidance, while all
        repository commits and project decisions were managed by the author.
      </div>
    </div>
  )
}

function SampleSelector({ onSelect, selected, samples }) {
  return (
    <div className="card">
      <h2>Sample Log Selector</h2>
      <select value={selected || ''} onChange={(e) => onSelect(e.target.value)}>
        <option value="">-- choose a sample --</option>
        {samples.map((s) => <option key={s} value={s}>{s}</option>)}
      </select>
    </div>
  )
}

function RawLogInput({ value, onChange, sourceType, setSourceType, onAnalyze, loading }) {
  return (
    <div className="card">
      <h2>Raw Log Input</h2>
      <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
        <select value={sourceType} onChange={(e) => setSourceType(e.target.value)} style={{ maxWidth: 180 }}>
          <option value="auth">auth</option>
          <option value="web">web</option>
          <option value="firewall">firewall</option>
          <option value="dns">dns</option>
          <option value="mixed">mixed</option>
        </select>
      </div>
      <textarea value={value} onChange={(e) => onChange(e.target.value)} placeholder="Paste log content here..." />
      <div style={{ marginTop: 8 }}>
        <button onClick={onAnalyze} disabled={loading}>{loading ? 'Analyzing...' : 'Analyze'}</button>
      </div>
    </div>
  )
}

function FindingsDashboard({ report }) {
  if (!report) return null
  return (
    <div className="card">
      <h2>Findings Dashboard</h2>
      <div className="grid-4">
        <div className="metric">
          <div className="label">Events</div>
          <div className="value">{report.total_events}</div>
        </div>
        <div className="metric">
          <div className="label">Findings</div>
          <div className="value">{report.total_findings}</div>
        </div>
        <div className="metric">
          <div className="label">Overall Score</div>
          <div className="value">{report.overall_score}</div>
        </div>
        <div className="metric">
          <div className="label">Severity</div>
          <div className="value"><Badge value={report.overall_severity} /></div>
        </div>
      </div>
    </div>
  )
}

function FindingsTable({ findings }) {
  if (!findings || findings.length === 0) return null
  return (
    <div className="card">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr>
            <th>Rule ID</th><th>Name</th><th>Severity</th><th>Score</th><th>Events</th><th>MITRE</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f, i) => (
            <tr key={i}>
              <td>{f.rule_id}</td>
              <td>{f.rule_name}</td>
              <td><Badge value={f.severity} /></td>
              <td>{f.score}</td>
              <td>{f.matched_events.length}</td>
              <td>{f.mitre_techniques.map((t) => <span key={t} className="pill">{t}</span>)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function MitrePanel({ findings }) {
  if (!findings || findings.length === 0) return null
  const seen = new Map()
  for (const f of findings) {
    for (const d of f.mitre_details || []) {
      if (!seen.has(d.id)) seen.set(d.id, d)
    }
  }
  if (seen.size === 0) return null
  return (
    <div className="card">
      <h2>MITRE ATT&amp;CK Mapping</h2>
      <table>
        <thead><tr><th>ID</th><th>Name</th><th>Tactic</th><th>Description</th></tr></thead>
        <tbody>
          {Array.from(seen.values()).map((t) => (
            <tr key={t.id}><td>{t.id}</td><td>{t.name}</td><td>{t.tactic}</td><td>{t.description}</td></tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function TimelinePanel({ timeline }) {
  if (!timeline || timeline.length === 0) return null
  return (
    <div className="card">
      <h2>Timeline</h2>
      <table>
        <thead><tr><th>Time</th><th>Source</th><th>Severity</th><th>Summary</th></tr></thead>
        <tbody>
          {timeline.map((t, i) => (
            <tr key={i}>
              <td>{t.timestamp}</td>
              <td>{t.source_type}</td>
              <td><Badge value={t.severity} /></td>
              <td>{t.summary}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function CorrelatedPanel({ incidents }) {
  if (!incidents || incidents.length === 0) return null
  return (
    <div className="card">
      <h2>Correlated Incidents</h2>
      <table>
        <thead><tr><th>ID</th><th>Actor</th><th>Score</th><th>Rules</th><th>Summary</th></tr></thead>
        <tbody>
          {incidents.map((i) => (
            <tr key={i.incident_id}>
              <td>{i.incident_id}</td>
              <td>{i.actor}</td>
              <td>{i.score}</td>
              <td>{i.rule_ids.map((r) => <span key={r} className="pill">{r}</span>)}</td>
              <td>{i.summary}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AiSummaryPanel({ summary }) {
  if (!summary) return null
  return (
    <div className="card">
      <h2>AI Summary (local mock)</h2>
      <pre style={{ whiteSpace: 'pre-wrap' }}>{summary}</pre>
    </div>
  )
}

function ReportsPanel({ sourceType, raw }) {
  const [markdown, setMarkdown] = useState('')
  const [json, setJson] = useState('')
  return (
    <div className="card">
      <h2>Reports</h2>
      <button onClick={async () => {
        const r = await api.reportMarkdown(sourceType, raw)
        setMarkdown(r.markdown)
      }}>Generate Markdown</button>
      <button className="secondary" onClick={async () => {
        const r = await api.reportJson(sourceType, raw)
        setJson(JSON.stringify(r, null, 2))
      }}>Generate JSON</button>
      {markdown && <><h3>Markdown</h3><pre>{markdown}</pre></>}
      {json && <><h3>JSON</h3><pre>{json}</pre></>}
    </div>
  )
}

function EvaluationPanel() {
  const [results, setResults] = useState(null)
  return (
    <div className="card">
      <h2>Detection Evaluation</h2>
      <button onClick={async () => setResults(await api.runAllScenarios())}>Run All Scenarios</button>
      {results && (
        <div style={{ marginTop: 8 }}>
          <div>Total: {results.total} | Passed: {results.passed} | Failed: {results.failed}</div>
          <table>
            <thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Matched</th><th>Missing</th></tr></thead>
            <tbody>
              {results.results.map((r) => (
                <tr key={r.scenario_id}>
                  <td>{r.scenario_id}</td>
                  <td>{r.name}</td>
                  <td>{r.passed ? <span className="badge passed">passed</span> : <span className="badge failed">failed</span>}</td>
                  <td>{r.matched_rule_ids.join(', ')}</td>
                  <td>{r.missing_rule_ids.join(', ') || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function DashboardSummaryPanel() {
  const [data, setData] = useState(null)
  useEffect(() => { api.dashboardSummary().then(setData).catch(() => {}) }, [])
  if (!data) return <div className="card"><h2>Dashboard Summary</h2><span className="muted">loading...</span></div>
  return (
    <div className="card">
      <h2>Dashboard Summary (all sample logs)</h2>
      <div className="grid-3">
        <div className="metric"><div className="label">Total findings</div><div className="value">{data.total_findings}</div></div>
        <div className="metric"><div className="label">Techniques</div><div className="value">{data.techniques.length}</div></div>
        <div className="metric"><div className="label">By severity</div><div className="value" style={{ fontSize: 12 }}>{Object.entries(data.by_severity).map(([k, v]) => <span key={k} className="pill">{k}: {v}</span>)}</div></div>
      </div>
      <h3>Top rules</h3>
      <table><thead><tr><th>Rule</th><th>Count</th></tr></thead><tbody>
        {data.top_rules.map((r) => <tr key={r.rule_id}><td>{r.rule_id} {r.rule_name}</td><td>{r.count}</td></tr>)}
      </tbody></table>
      <h3>Top source IPs</h3>
      <table><thead><tr><th>IP</th><th>Count</th></tr></thead><tbody>
        {data.top_source_ips.map((r) => <tr key={r.ip}><td>{r.ip}</td><td>{r.count}</td></tr>)}
      </tbody></table>
    </div>
  )
}

function ReviewerQuickPath() {
  return (
    <div className="card">
      <h2>Reviewer Quick Path</h2>
      <ol className="review-path">
        <li>Open the Backend Status card to confirm the FastAPI service is reachable.</li>
        <li>Use the Sample Log Selector to load <code>mixed_security_events.log</code>.</li>
        <li>Click <b>Analyze</b> to populate Findings, MITRE mapping, timeline, and correlation panels.</li>
        <li>Open the Reports panel and generate the Markdown report to see the AI-style summary.</li>
        <li>Open the Detection Evaluation panel and run all scenarios; expect all to pass.</li>
        <li>Read the Dashboard Summary panel to see aggregated state across all sample logs.</li>
        <li>v2: open the Alert Triage Queue, Incident Cases, Entity Risk, Kill Chain, MITRE Coverage, Rule Tuning, and SOC Report panels.</li>
      </ol>
    </div>
  )
}

function SocOverview() {
  const [data, setData] = useState(null)
  const load = async () => {
    const [tri, cas, ent, cov, evalRun, dash] = await Promise.all([
      api.triageSample(),
      api.casesSample(),
      api.entitiesSample(),
      api.coverageMitre(),
      api.runAllScenarios(),
      api.dashboardSummary(),
    ])
    const highRiskEntities = (ent.entities || []).filter((e) => e.severity === 'high' || e.severity === 'critical').length
    const highestScore = (ent.entities || []).reduce((m, e) => Math.max(m, e.risk_score), 0)
    setData({
      totalAlerts: tri.alerts.length,
      openCases: (cas.cases || []).filter((c) => c.status === 'open').length,
      highRiskEntities,
      coverageRate: cov.coverage_summary.coverage_rate,
      evalPassRate: evalRun.total ? evalRun.passed / evalRun.total : 0,
      highestScore,
      totalFindings: dash.total_findings,
    })
  }
  useEffect(() => { load().catch(() => {}) }, [])
  if (!data) return <div className="card"><h2>SOC Overview</h2><span className="muted">loading...</span></div>
  return (
    <div className="card">
      <h2>SOC Overview</h2>
      <div className="grid-4">
        <div className="metric"><div className="label">Total alerts</div><div className="value">{data.totalAlerts}</div></div>
        <div className="metric"><div className="label">Open cases</div><div className="value">{data.openCases}</div></div>
        <div className="metric"><div className="label">High-risk entities</div><div className="value">{data.highRiskEntities}</div></div>
        <div className="metric"><div className="label">MITRE coverage</div><div className="value">{Math.round(data.coverageRate * 100)}%</div></div>
        <div className="metric"><div className="label">Eval pass rate</div><div className="value">{Math.round(data.evalPassRate * 100)}%</div></div>
        <div className="metric"><div className="label">Highest risk score</div><div className="value">{data.highestScore}</div></div>
        <div className="metric"><div className="label">Total findings</div><div className="value">{data.totalFindings}</div></div>
      </div>
    </div>
  )
}

function TriageQueuePanel() {
  const [data, setData] = useState(null)
  return (
    <div className="card">
      <h2>Alert Triage Queue</h2>
      <button onClick={async () => setData(await api.triageSample())}>Generate Alert Queue</button>
      {data && (
        <>
          <div className="muted" style={{ marginTop: 6 }}>
            Total: {data.queue_summary.total_alerts} | Open: {data.queue_summary.open_alerts} | Priorities: {JSON.stringify(data.queue_summary.priority_counts)}
          </div>
          <table>
            <thead><tr><th>ID</th><th>Severity</th><th>Priority</th><th>Title</th><th>Src IPs</th><th>MITRE</th><th>Status</th><th>FP likelihood</th></tr></thead>
            <tbody>
              {data.alerts.map((a) => (
                <tr key={a.alert_id}>
                  <td>{a.alert_id}</td>
                  <td><Badge value={a.severity} /></td>
                  <td><span className="pill">{a.priority}</span></td>
                  <td>{a.title}</td>
                  <td>{a.src_ips.join(', ')}</td>
                  <td>{a.mitre_techniques.map((t) => <span key={t} className="pill">{t}</span>)}</td>
                  <td>{a.status}</td>
                  <td>{a.false_positive && <Badge value={a.false_positive.likelihood === 'high' ? 'high' : a.false_positive.likelihood === 'medium' ? 'medium' : 'low'} />} <span className="muted">{a.false_positive ? a.false_positive.likelihood : ''}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}

function CasesPanel() {
  const [data, setData] = useState(null)
  return (
    <div className="card">
      <h2>Incident Cases</h2>
      <button onClick={async () => setData(await api.casesSample())}>Generate Cases</button>
      {data && (
        <>
          <div className="muted" style={{ marginTop: 6 }}>
            Total: {data.case_summary.total_cases} | Open: {data.case_summary.open_cases}
          </div>
          <table>
            <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Priority</th><th>Type</th><th>Alerts</th><th>Actions</th></tr></thead>
            <tbody>
              {data.cases.map((c) => (
                <tr key={c.case_id}>
                  <td>{c.case_id}</td>
                  <td>{c.title}</td>
                  <td><Badge value={c.severity} /></td>
                  <td><span className="pill">{c.priority}</span></td>
                  <td>{c.case_type}</td>
                  <td>{c.related_alert_ids.length}</td>
                  <td>
                    <ul style={{ margin: 0, paddingLeft: 16 }}>
                      {c.recommended_actions.slice(0, 3).map((a, i) => <li key={i} style={{ fontSize: 11 }}>{a}</li>)}
                    </ul>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}

function EntityRiskPanel() {
  const [data, setData] = useState(null)
  return (
    <div className="card">
      <h2>Entity Risk Profiles</h2>
      <button onClick={async () => setData(await api.entitiesSample())}>Build Entity Profiles</button>
      {data && (
        <>
          <div className="muted" style={{ marginTop: 6 }}>
            Total: {data.entity_summary.total_entities} | High risk: {data.entity_summary.high_risk_entities}
          </div>
          <table>
            <thead><tr><th>Entity</th><th>Type</th><th>Risk score</th><th>Severity</th><th>Events</th><th>Findings</th><th>Alerts</th><th>MITRE</th></tr></thead>
            <tbody>
              {data.entities.slice(0, 30).map((e, i) => (
                <tr key={i}>
                  <td>{e.entity_id}</td>
                  <td>{e.entity_type}</td>
                  <td>{e.risk_score}</td>
                  <td><Badge value={e.severity} /></td>
                  <td>{e.event_count}</td>
                  <td>{e.finding_count}</td>
                  <td>{e.alert_count}</td>
                  <td>{e.mitre_techniques.map((t) => <span key={t} className="pill">{t}</span>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}

function KillChainPanel() {
  const [data, setData] = useState(null)
  return (
    <div className="card">
      <h2>Kill Chain View</h2>
      <button onClick={async () => setData(await api.killChainSample())}>Build Kill Chain</button>
      {data && (
        <>
          <div className="muted" style={{ marginTop: 6 }}>{data.narrative}</div>
          <table>
            <thead><tr><th>Observed</th><th>Stage</th><th>Findings</th><th>MITRE techniques</th></tr></thead>
            <tbody>
              {data.stages.map((s) => (
                <tr key={s.stage}>
                  <td>{s.observed ? <span className="badge passed">yes</span> : <span className="pill">no</span>}</td>
                  <td>{s.stage}</td>
                  <td>{s.finding_count}</td>
                  <td>{s.mitre_techniques.map((t) => <span key={t} className="pill">{t}</span>)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}

function CoveragePanel() {
  const [data, setData] = useState(null)
  return (
    <div className="card">
      <h2>MITRE Coverage Matrix</h2>
      <button onClick={async () => setData(await api.coverageMitre())}>Load Coverage Matrix</button>
      {data && (
        <>
          <div className="muted" style={{ marginTop: 6 }}>
            Coverage rate: {Math.round(data.coverage_summary.coverage_rate * 100)}% ({data.coverage_summary.covered}/{data.coverage_summary.total_techniques})
          </div>
          <table>
            <thead><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Covered</th><th>Rules</th><th>Strength</th></tr></thead>
            <tbody>
              {data.matrix.map((e) => (
                <tr key={e.technique_id}>
                  <td>{e.technique_id}</td>
                  <td>{e.technique_name}</td>
                  <td>{e.tactic}</td>
                  <td>{e.covered ? <span className="badge passed">yes</span> : <span className="badge failed">no</span>}</td>
                  <td>{e.rule_ids.map((r) => <span key={r} className="pill">{r}</span>)}</td>
                  <td>{e.coverage_strength}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}

function RuleTuningPanel() {
  const [data, setData] = useState(null)
  return (
    <div className="card">
      <h2>Rule Tuning</h2>
      <button onClick={async () => setData(await api.rulesTuning())}>Analyze Rule Tuning</button>
      {data && (
        <>
          <h3>Rule performance</h3>
          <table>
            <thead><tr><th>Rule</th><th>Triggered</th><th>Expected</th><th>Missed</th><th>Overtrigger</th><th>Recommendation</th></tr></thead>
            <tbody>
              {data.rule_performance.map((p) => (
                <tr key={p.rule_id}>
                  <td>{p.rule_id}</td>
                  <td>{p.triggered_count}</td>
                  <td>{p.expected_count}</td>
                  <td>{p.missed_count}</td>
                  <td>{p.possible_overtrigger}</td>
                  <td style={{ fontSize: 11 }}>{p.tuning_recommendation}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>Tuning recommendations</h3>
          <ul>
            {data.tuning_recommendations.map((r, i) => (
              <li key={i} style={{ fontSize: 12 }}><b>{r.rule_id}</b> [{r.recommendation_type}]: {r.suggested_change}</li>
            ))}
          </ul>
          <h3>Detection gaps</h3>
          <ul>
            {data.detection_gaps.length === 0 && <li className="muted">No gaps.</li>}
            {data.detection_gaps.map((g, i) => (
              <li key={i} style={{ fontSize: 12 }}>{g.scenario_id}: missing {g.missing_rule_ids.join(', ')}</li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}

function SocReportPanel({ sourceType, raw }) {
  const [json, setJson] = useState('')
  const [markdown, setMarkdown] = useState('')
  const copy = (txt) => { try { navigator.clipboard.writeText(txt) } catch (e) {} }
  return (
    <div className="card">
      <h2>SOC Report</h2>
      <button onClick={async () => setJson(JSON.stringify(await api.reportSocJson(sourceType, raw), null, 2))}>Generate SOC JSON Report</button>
      <button className="secondary" onClick={async () => {
        const r = await api.reportSocMarkdown(sourceType, raw)
        setMarkdown(r.markdown)
      }}>Generate SOC Markdown Report</button>
      {json && <><h3>SOC JSON <button onClick={() => copy(json)}>Copy JSON</button></h3><pre>{json}</pre></>}
      {markdown && <><h3>SOC Markdown <button onClick={() => copy(markdown)}>Copy Markdown</button></h3><pre>{markdown}</pre></>}
    </div>
  )
}

export default function App() {
  const [samples, setSamples] = useState([])
  const [selectedSample, setSelectedSample] = useState('')
  const [sourceType, setSourceType] = useState('auth')
  const [raw, setRaw] = useState('')
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    api.sampleLogs().then((d) => setSamples(d.sample_logs)).catch(() => {})
  }, [])

  useEffect(() => {
    if (!selectedSample) return
    api.sampleLogContent(selectedSample).then((d) => {
      setRaw(d.content)
      setSourceType(d.source_type)
    }).catch(() => {})
  }, [selectedSample])

  const runAnalyze = async () => {
    setLoading(true)
    try {
      const r = await api.analyze(sourceType, raw)
      setReport(r)
    } finally { setLoading(false) }
  }

  return (
    <div className="container">
      <div className="header">
        <h1>Security Log AI Assistant — SOC Platform</h1>
        <span className="muted">v2.0-rc</span>
      </div>
      <BackendStatusCard />
      <DisclosureCard />
      <ReviewerQuickPath />
      <SocOverview />
      <div className="row">
        <SampleSelector samples={samples} selected={selectedSample} onSelect={setSelectedSample} />
        <RawLogInput value={raw} onChange={setRaw} sourceType={sourceType} setSourceType={setSourceType} onAnalyze={runAnalyze} loading={loading} />
      </div>
      <FindingsDashboard report={report} />
      <FindingsTable findings={report?.findings} />
      <MitrePanel findings={report?.findings} />
      <TimelinePanel timeline={report?.timeline} />
      <CorrelatedPanel incidents={report?.correlated_incidents} />
      <AiSummaryPanel summary={report?.ai_summary} />
      <TriageQueuePanel />
      <CasesPanel />
      <EntityRiskPanel />
      <KillChainPanel />
      <CoveragePanel />
      <RuleTuningPanel />
      <ReportsPanel sourceType={sourceType} raw={raw} />
      <SocReportPanel sourceType={sourceType} raw={raw} />
      <EvaluationPanel />
      <DashboardSummaryPanel />
    </div>
  )
}
