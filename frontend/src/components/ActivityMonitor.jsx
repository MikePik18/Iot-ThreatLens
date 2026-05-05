const severityBuckets = [
  { label: 'Low',      min: 1, max: 2, color: 'var(--low)' },
  { label: 'Medium',   min: 3, max: 3, color: 'var(--medium)' },
  { label: 'High',     min: 4, max: 4, color: 'var(--high)' },
  { label: 'Critical', min: 5, max: 5, color: 'var(--critical)' },
];

export default function ActivityMonitor({ threats, maliciousCount, aggregates, avgConfidence: avgConfidenceProp }) {
  const aggSev = aggregates?.severity_dist;

  const counts = aggSev
    ? [
        (aggSev['Low (≤2)']   ?? 0),
        (aggSev['Medium (3)'] ?? 0),
        (aggSev['High (4)']   ?? 0),
        (aggSev['Critical (5)'] ?? 0),
      ]
    : severityBuckets.map(b =>
        threats.filter(t => t.severity >= b.min && t.severity <= b.max).length
      );

  const maxCount = Math.max(...counts, 1);

  const totalThreats = maliciousCount ?? threats.length;

  const critical = aggSev
    ? (aggSev['Critical (5)'] ?? 0)
    : threats.filter(t => t.severity >= 5).length;

  const avgConfidence = avgConfidenceProp != null
    ? avgConfidenceProp
    : threats.length > 0
      ? (threats.reduce((sum, t) => sum + t.confidence, 0) / threats.length * 100).toFixed(1)
      : 0;

  return (
    <div className="activity-monitor">
      <div className="section-header">
        <h2 className="section-title">Severity Breakdown</h2>
      </div>

      <div className="activity-chart" style={{ alignItems: 'flex-end', gap: '1rem', padding: '1rem 1rem 0 1rem' }}>
        {severityBuckets.map((bucket, i) => (
          <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.4rem', height: '100%', justifyContent: 'flex-end' }}>
            <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: '0.85rem', color: bucket.color, fontWeight: 600 }}>
              {counts[i]}
            </span>
            <div style={{
              width: '100%',
              height: `${(counts[i] / maxCount) * 75}%`,
              minHeight: counts[i] > 0 ? '8px' : '2px',
              background: bucket.color,
              borderRadius: '4px 4px 0 0',
              opacity: counts[i] > 0 ? 1 : 0.2,
              transition: 'height 0.5s ease',
            }} />
            <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: '0.7rem', color: 'var(--text-secondary)', paddingBottom: '0.5rem' }}>
              {bucket.label}
            </span>
          </div>
        ))}
      </div>

      <div className="quick-stats">
        <div className="quick-stat">
          <span className="quick-stat-label">Total Threats</span>
          <span className="quick-stat-value" style={{ color: 'var(--critical)' }}>{totalThreats.toLocaleString()}</span>
        </div>
        <div className="quick-stat">
          <span className="quick-stat-label">Avg Confidence</span>
          <span className="quick-stat-value" style={{ color: 'var(--accent-cyan)' }}>{avgConfidence}%</span>
        </div>
        <div className="quick-stat">
          <span className="quick-stat-label">Critical Threats</span>
          <span className="quick-stat-value" style={{ color: 'var(--critical)' }}>{critical}</span>
        </div>
      </div>
    </div>
  );
}
