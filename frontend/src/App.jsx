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
      </ol>
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
        <h1>Security Log AI Assistant</h1>
        <span className="muted">v1.0-rc</span>
      </div>
      <BackendStatusCard />
      <DisclosureCard />
      <ReviewerQuickPath />
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
      <ReportsPanel sourceType={sourceType} raw={raw} />
      <EvaluationPanel />
      <DashboardSummaryPanel />
    </div>
  )
}
