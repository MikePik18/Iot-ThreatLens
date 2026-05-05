export default function StatsGrid({ threats, maliciousCount, avgConfidence, aggregates }) {
  const total = maliciousCount ?? threats.length;

  const critical = aggregates?.severity_dist
    ? (aggregates.severity_dist['Critical (5)'] ?? 0)
    : threats.filter(t => t.severity >= 5).length;

  const highPlus = aggregates?.severity_dist
    ? (aggregates.severity_dist['Critical (5)'] ?? 0) + (aggregates.severity_dist['High (4)'] ?? 0)
    : threats.filter(t => t.severity >= 4).length;

  const displayConfidence = avgConfidence != null
    ? avgConfidence
    : threats.length > 0
      ? (threats.reduce((sum, t) => sum + t.confidence, 0) / threats.length * 100).toFixed(1)
      : 0;

  return (
    <div className="stats-grid">
      <div className="stat-card">
        <div className="stat-label">Total Threats Detected</div>
        <div className="stat-value" style={{ color: 'var(--critical)' }}>{total.toLocaleString()}</div>
        <div className="stat-change">from current analysis</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Critical Incidents</div>
        <div className="stat-value" style={{ color: 'var(--critical)' }}>{critical}</div>
        <div className="stat-change up">{critical > 0 ? 'requires immediate action' : 'none detected'}</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">Model Confidence</div>
        <div className="stat-value" style={{ color: 'var(--accent-cyan)' }}>{displayConfidence}%</div>
        <div className="stat-change">avg across all detections</div>
      </div>
      <div className="stat-card">
        <div className="stat-label">High+ Severity</div>
        <div className="stat-value" style={{ color: 'var(--high)' }}>{highPlus}</div>
        <div className="stat-change">of detected threats</div>
      </div>
    </div>
  );
}
