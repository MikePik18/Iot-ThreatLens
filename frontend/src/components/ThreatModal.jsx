function getSeverityLabel(num) {
  if (num >= 5) return 'critical';
  if (num >= 4) return 'high';
  if (num >= 3) return 'medium';
  return 'low';
}

export default function ThreatModal({ threat, onClose, onQueryAI, querying }) {
  if (!threat) return null;

  // not queried yet
  const hasAiAnalysis = !!threat.summary;

  return (
    <div className="modal active" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal-content">
        <button className="modal-close" onClick={onClose}>×</button>

        <div className="modal-header">
          <h2 className="modal-title">
            {threat.attack_type}
            <span className={`severity-badge ${getSeverityLabel(threat.severity)}`}>
              SEVERITY {threat.severity}
            </span>
          </h2>
          <div className="threat-meta">
            <span>📡 {threat.proto}</span>
            <span>🔌 {threat.service}</span>
            <span>🔗 {threat.conn_state}</span>
            <span>🎯 {(threat.confidence * 100).toFixed(1)}% confidence</span>
          </div>
        </div>

        {!hasAiAnalysis ? (
          <div>
            <div className="tech-details" style={{ marginBottom: '1.5rem' }}>
              <h4 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Raw Flow Data</h4>
              <div className="tech-details-grid">
                <div className="tech-detail-item">
                  <div className="tech-detail-label">Protocol</div>
                  <div className="tech-detail-value">{threat.proto}</div>
                </div>
                <div className="tech-detail-item">
                  <div className="tech-detail-label">Service</div>
                  <div className="tech-detail-value">{threat.service}</div>
                </div>
                <div className="tech-detail-item">
                  <div className="tech-detail-label">Connection State</div>
                  <div className="tech-detail-value">{threat.conn_state}</div>
                </div>
                <div className="tech-detail-item">
                  <div className="tech-detail-label">ML Confidence</div>
                  <div className="tech-detail-value">{(threat.confidence * 100).toFixed(1)}%</div>
                </div>
                <div className="tech-detail-item">
                  <div className="tech-detail-label">Orig Bytes</div>
                  <div className="tech-detail-value">{threat.orig_bytes?.toFixed(0) ?? '—'}</div>
                </div>
                <div className="tech-detail-item">
                  <div className="tech-detail-label">Resp Bytes</div>
                  <div className="tech-detail-value">{threat.resp_bytes?.toFixed(0) ?? '—'}</div>
                </div>
              </div>
            </div>

            <button
              onClick={onQueryAI}
              disabled={querying}
              style={{
                width: '100%',
                padding: '1rem',
                background: querying ? 'transparent' : 'linear-gradient(90deg, rgba(0,217,255,0.1), rgba(0,102,255,0.1))',
                border: '1px solid var(--accent-cyan)',
                borderRadius: '8px',
                color: querying ? 'var(--text-secondary)' : 'var(--accent-cyan)',
                fontFamily: 'IBM Plex Mono, monospace',
                fontSize: '0.85rem',
                letterSpacing: '2px',
                cursor: querying ? 'not-allowed' : 'pointer',
                transition: 'all 0.3s ease',
                animation: querying ? 'pulse 1.5s ease-in-out infinite' : 'none',
              }}
            >
              {querying ? '⟳  QUERYING AI AGENT...' : '◈  QUERY AI AGENT'}
            </button>
          </div>
        ) : (
          // has AI analysis
          <>
            <div className="ai-section">
              <h3>AI Analysis</h3>
              <p className="ai-content">{threat.summary}</p>
            </div>

            <div className="ai-section">
              <h3>Key Indicators</h3>
              <ul className="mitigation-list">
                {threat.key_indicators?.map((item, i) => <li key={i}>{item}</li>)}
              </ul>
            </div>

            <div className="ai-section">
              <h3>Recommended Mitigations</h3>
              <ul className="mitigation-list">
                {threat.mitigations?.map((item, i) => <li key={i}>{item}</li>)}
              </ul>
            </div>

            <div className="ai-section">
              <h3>Log Signatures to Watch</h3>
              <ul className="mitigation-list">
                {threat.log_signatures?.map((item, i) => <li key={i}>{item}</li>)}
              </ul>
            </div>

            <div className="tech-details">
              <h4 style={{ marginBottom: '1rem', color: 'var(--text-secondary)' }}>Technical Details</h4>
              <div className="tech-details-grid">
                <div className="tech-detail-item">
                  <div className="tech-detail-label">Protocol</div>
                  <div className="tech-detail-value">{threat.proto}</div>
                </div>
                <div className="tech-detail-item">
                  <div className="tech-detail-label">Service</div>
                  <div className="tech-detail-value">{threat.service}</div>
                </div>
                <div className="tech-detail-item">
                  <div className="tech-detail-label">Connection State</div>
                  <div className="tech-detail-value">{threat.conn_state}</div>
                </div>
                <div className="tech-detail-item">
                  <div className="tech-detail-label">ML Confidence</div>
                  <div className="tech-detail-value">{(threat.confidence * 100).toFixed(1)}%</div>
                </div>
                <div className="tech-detail-item">
                  <div className="tech-detail-label">Severity Score</div>
                  <div className="tech-detail-value">{threat.severity}/5</div>
                </div>
                <div className="tech-detail-item">
                  <div className="tech-detail-label">Impact</div>
                  <div className="tech-detail-value" style={{ fontSize: '0.8rem' }}>{threat.impact}</div>
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
