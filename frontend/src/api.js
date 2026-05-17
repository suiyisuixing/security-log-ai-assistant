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
  // v2
  triageSample: () => jsonRequest('/triage/sample'),
  triageAnalyze: (logType, raw, includeCorrelation = true) =>
    jsonRequest('/triage/analyze', { method: 'POST', body: JSON.stringify({ log_type: logType, raw_logs: raw, include_correlation: includeCorrelation }) }),
  casesSample: () => jsonRequest('/cases/sample'),
  casesFromAnalysis: (logType, raw, includeCorrelation = true) =>
    jsonRequest('/cases/from-analysis', { method: 'POST', body: JSON.stringify({ log_type: logType, raw_logs: raw, include_correlation: includeCorrelation }) }),
  falsePositiveReview: (logType, raw) =>
    jsonRequest('/false-positive/review', { method: 'POST', body: JSON.stringify({ log_type: logType, raw_logs: raw }) }),
  rulesTuning: () => jsonRequest('/rules/tuning'),
  entitiesSample: () => jsonRequest('/entities/sample'),
  entitiesAnalyze: (logType, raw) =>
    jsonRequest('/entities/analyze', { method: 'POST', body: JSON.stringify({ log_type: logType, raw_logs: raw }) }),
  killChainSample: () => jsonRequest('/kill-chain/sample'),
  killChainAnalyze: (logType, raw, includeCorrelation = true) =>
    jsonRequest('/kill-chain/analyze', { method: 'POST', body: JSON.stringify({ log_type: logType, raw_logs: raw, include_correlation: includeCorrelation }) }),
  coverageMitre: () => jsonRequest('/coverage/mitre'),
  reportSocJson: (sourceType, raw) =>
    jsonRequest('/report/soc-json', { method: 'POST', body: JSON.stringify({ source_type: sourceType, raw_logs: raw }) }),
  reportSocMarkdown: (sourceType, raw) =>
    jsonRequest('/report/soc-markdown', { method: 'POST', body: JSON.stringify({ source_type: sourceType, raw_logs: raw }) }),
  // v3
  datasets: () => jsonRequest('/datasets'),
  datasetContent: (id) => jsonRequest(`/datasets/${encodeURIComponent(id)}`),
  datasetAnalyze: (id) => jsonRequest(`/datasets/analyze/${encodeURIComponent(id)}`, { method: 'POST' }),
  detectionEngineeringRules: () => jsonRequest('/detection-engineering/rules'),
  detectionEngineeringReport: () => jsonRequest('/detection-engineering/report'),
  detectionEngineeringMetrics: () => jsonRequest('/detection-engineering/metrics'),
  metricsEvaluation: () => jsonRequest('/metrics/evaluation'),
  metricsRules: () => jsonRequest('/metrics/rules'),
  playbooks: () => jsonRequest('/playbooks'),
  playbooksRecommend: (logType, raw) =>
    jsonRequest('/playbooks/recommend', { method: 'POST', body: JSON.stringify({ log_type: logType, raw_logs: raw }) }),
  workflowSample: () => jsonRequest('/workflow/sample'),
  workflowSimulate: (logType, raw) =>
    jsonRequest('/workflow/simulate', { method: 'POST', body: JSON.stringify({ log_type: logType, raw_logs: raw }) }),
  reportExecutive: (sourceType, raw) =>
    jsonRequest('/report/executive', { method: 'POST', body: JSON.stringify({ source_type: sourceType, raw_logs: raw }) }),
  reportAnalyst: (sourceType, raw) =>
    jsonRequest('/report/analyst', { method: 'POST', body: JSON.stringify({ source_type: sourceType, raw_logs: raw }) }),
  reportDetectionEngineering: () =>
    jsonRequest('/report/detection-engineering', { method: 'POST' }),
}
