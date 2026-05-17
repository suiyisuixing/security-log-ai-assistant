const BASE = '/api-backend'

async function jsonRequest(path, options = {}) {
  const res = await fetch(BASE + path, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`HTTP ${res.status}: ${text}`)
  }
  return res.json()
}

export const api = {
  health: () => jsonRequest('/health'),
  root: () => jsonRequest('/'),
  sampleLogs: () => jsonRequest('/sample-logs'),
  sampleLogContent: (name) => jsonRequest(`/sample-logs/${encodeURIComponent(name)}`),
  rules: () => jsonRequest('/rules'),
  mitre: () => jsonRequest('/mitre'),
  parse: (sourceType, raw) =>
    jsonRequest('/parse', { method: 'POST', body: JSON.stringify({ source_type: sourceType, raw_logs: raw }) }),
  analyze: (sourceType, raw) =>
    jsonRequest('/analyze', { method: 'POST', body: JSON.stringify({ source_type: sourceType, raw_logs: raw }) }),
  analyzeSample: (name) =>
    jsonRequest(`/analyze-sample/${encodeURIComponent(name)}`, { method: 'POST' }),
  reportJson: (sourceType, raw) =>
    jsonRequest('/report/json', { method: 'POST', body: JSON.stringify({ source_type: sourceType, raw_logs: raw }) }),
  reportMarkdown: (sourceType, raw) =>
    jsonRequest('/report/markdown', { method: 'POST', body: JSON.stringify({ source_type: sourceType, raw_logs: raw }) }),
  scenarios: () => jsonRequest('/evaluation/scenarios'),
  runAllScenarios: () => jsonRequest('/evaluation/run', { method: 'POST' }),
  runScenario: (id) => jsonRequest(`/evaluation/run-one/${encodeURIComponent(id)}`, { method: 'POST' }),
  dashboardSummary: () => jsonRequest('/dashboard/summary'),
  apiSurface: () => jsonRequest('/api/surface'),
}
