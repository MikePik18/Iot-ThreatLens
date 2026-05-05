import { useState, useEffect, useCallback } from 'react';
import mockThreats from '../data/mockThreats';
import API_URL from '../config';

function getSeverityLabel(num) {
  if (num >= 5) return 'critical';
  if (num >= 4) return 'high';
  if (num >= 3) return 'medium';
  return 'low';
}

const selectStyle = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  color: 'var(--text-secondary)',
  borderRadius: '6px',
  padding: '0.3rem 0.6rem',
  fontFamily: 'IBM Plex Mono, monospace',
  fontSize: '0.75rem',
  cursor: 'pointer',
  outline: 'none',
};

const PAGE_SIZE = 15;

export default function ThreatFeed({ onSelectThreat, useServer, aiCache = {}, threatKey = () => '' }) {
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [attackFilter, setAttackFilter]     = useState('ALL');
  const [sortDir, setSortDir]               = useState('desc');
  const [page, setPage]                     = useState(0);

  const [items, setItems]           = useState([]);
  const [total, setTotal]           = useState(0);
  const [totalPages, setTotalPages] = useState(1);
  const [attackTypes, setAttackTypes] = useState([]);
  const [loading, setLoading]       = useState(false);

  const fetchThreats = useCallback(async (sev, atk, sort, pg) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        page: pg, page_size: PAGE_SIZE,
        severity: sev, attack_type: atk, sort_dir: sort,
      });
      const res = await fetch(`${API_URL}/threats?${params}`);
      const data = await res.json();
      setItems(data.items);
      setTotal(data.total);
      setTotalPages(data.total_pages);
      setAttackTypes(data.attack_types);
    } catch {
      // something went wrong, just show nothing
      setItems([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (useServer) {
      fetchThreats(severityFilter, attackFilter, sortDir, page);
    }
  }, [useServer, severityFilter, attackFilter, sortDir, page, fetchThreats]);

  // demo mode - no server, filter locally
  const localItems = (() => {
    if (useServer) return items;
    return mockThreats
      .filter(t => {
        if (severityFilter === 'ALL')      return true;
        if (severityFilter === 'CRITICAL') return t.severity === 5;
        if (severityFilter === 'HIGH')     return t.severity === 4;
        if (severityFilter === 'MEDIUM')   return t.severity === 3;
        if (severityFilter === 'LOW')      return t.severity <= 2;
        return true;
      })
      .filter(t => attackFilter === 'ALL' || t.attack_type === attackFilter)
      .sort((a, b) => sortDir === 'desc' ? b.confidence - a.confidence : a.confidence - b.confidence)
      .slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  })();

  const displayItems = useServer ? items : localItems;
  const displayTotal = useServer ? total : mockThreats.length;
  const displayTotalPages = useServer ? totalPages : Math.ceil(mockThreats.length / PAGE_SIZE);
  const displayAttackTypes = useServer ? attackTypes : [...new Set(mockThreats.map(t => t.attack_type))].sort();

  function handleSeverityChange(tab) {
    setSeverityFilter(tab);
    setAttackFilter('ALL');
    setPage(0);
  }

  function handleAttackFilterChange(val) {
    setAttackFilter(val);
    setPage(0);
  }

  function handleSortChange(val) {
    setSortDir(val);
    setPage(0);
  }

  const hasAiAnalysis = t => !!t.summary;

  return (
    <div className="threat-feed">
      <div className="section-header">
        <h2 className="section-title">Active Threats</h2>
        <div className="filter-tabs">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(tab => (
            <button
              key={tab}
              className={`filter-tab ${severityFilter === tab ? 'active' : ''}`}
              onClick={() => handleSeverityChange(tab)}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', gap: '0.75rem', padding: '0 0 0.75rem 0', alignItems: 'center' }}>
        <select value={attackFilter} onChange={e => handleAttackFilterChange(e.target.value)} style={selectStyle}>
          <option value="ALL">All Attack Types</option>
          {displayAttackTypes.map(type => (
            <option key={type} value={type}>{type}</option>
          ))}
        </select>

        <select value={sortDir} onChange={e => handleSortChange(e.target.value)} style={selectStyle}>
          <option value="desc">Confidence: High → Low</option>
          <option value="asc">Confidence: Low → High</option>
        </select>

        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
            {displayTotal.toLocaleString()} total
          </span>
          <button
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={page === 0}
            style={{ ...selectStyle, padding: '0.3rem 0.6rem', opacity: page === 0 ? 0.3 : 1 }}
          >
            ‹
          </button>
          <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontSize: '0.75rem', color: 'var(--text-secondary)', minWidth: '4rem', textAlign: 'center' }}>
            {page + 1} / {displayTotalPages}
          </span>
          <button
            onClick={() => setPage(p => Math.min(displayTotalPages - 1, p + 1))}
            disabled={page >= displayTotalPages - 1}
            style={{ ...selectStyle, padding: '0.3rem 0.6rem', opacity: page >= displayTotalPages - 1 ? 0.3 : 1 }}
          >
            ›
          </button>
        </div>
      </div>

      <div className="threat-list">
        {loading ? (
          <div style={{ color: 'var(--accent-cyan)', fontFamily: 'IBM Plex Mono, monospace', fontSize: '0.85rem', textAlign: 'center', padding: '2rem' }}>
            loading...
          </div>
        ) : displayItems.length === 0 ? (
          <div style={{ color: 'var(--text-secondary)', textAlign: 'center', padding: '2rem' }}>
            no threats matching this filter
          </div>
        ) : (
          displayItems.map((threat, i) => {
            const flowNum = String(threat.flow_id ?? (page * PAGE_SIZE + i + 1)).padStart(4, '0');
            return (
            <div
              key={i}
              className={`threat-item ${getSeverityLabel(threat.severity)}`}
              onClick={() => onSelectThreat(threat)}
            >
              <div className="threat-header">
                <div className="threat-type">
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', fontFamily: 'IBM Plex Mono, monospace', marginRight: '0.5rem' }}>#{flowNum}</span>
                  {threat.attack_type}
                </div>
                <div className={`severity-badge ${getSeverityLabel(threat.severity)}`}>
                  SEVERITY {threat.severity}
                </div>
              </div>
              <div className="threat-meta">
                <span>📡 {threat.proto}</span>
                <span>🔌 {threat.service}</span>
                <span>🔗 {threat.conn_state}</span>
                <span>🎯 {(threat.confidence * 100).toFixed(1)}% confidence</span>
              </div>
              <div className="threat-description">
                {hasAiAnalysis(threat)
                  ? threat.summary
                  : aiCache[threatKey(threat)]?.summary ?? 'Click to query the AI agent for a full threat analysis.'}
              </div>
            </div>
          )})
        )}
      </div>
    </div>
  );
}
