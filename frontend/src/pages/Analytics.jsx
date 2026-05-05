import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, LabelList
} from 'recharts';
import { useLocation } from 'react-router-dom';
import Header from '../components/Header';
import mockThreats from '../data/mockThreats';

const COLORS = {
  critical: '#ff0055',
  high: '#ff6b35',
  medium: '#ffa500',
  low: '#ffd700',
  tcp: '#00d9ff',
  udp: '#7c3aed',
  icmp: '#00ff88',
  other: '#9ca3af',
};

const tooltipStyle = {
  backgroundColor: '#111827',
  border: '1px solid rgba(0, 217, 255, 0.2)',
  borderRadius: '8px',
  color: '#e5e7eb',
  fontFamily: 'IBM Plex Mono, monospace',
  fontSize: '0.85rem',
};

const cardStyle = {
  background: 'var(--bg-secondary)',
  border: '1px solid var(--border)',
  borderRadius: '12px',
  padding: '1.5rem',
};

const titleStyle = {
  fontSize: '1.1rem', fontWeight: 600, letterSpacing: '1px',
  marginBottom: '1.5rem', color: 'var(--text-primary)',
  display: 'flex', alignItems: 'center', gap: '0.5rem',
};

export default function Analytics() {
  const location = useLocation();

  const isDemo = sessionStorage.getItem('demoMode') === 'true';
  const saved = isDemo ? null : JSON.parse(localStorage.getItem('analysisResults') || 'null');
  const stateSource = isDemo ? null : (location.state ?? saved);

  const threats = stateSource?.threats ?? mockThreats;
  const maliciousCount = stateSource?.maliciousCount;
  const avgConfidence = stateSource?.avgConfidence;
  const agg = stateSource?.aggregates;

  // attack type — use full aggregate from backend if available (covers ALL flows)
  const attackTypeCounts = agg?.attack_type_dist
    ? Object.entries(agg.attack_type_dist)
        .sort((a, b) => b[1] - a[1])
        .map(([name, count]) => ({ name, count }))
    : threats
        .filter(t => t.attack_type)
        .reduce((acc, t) => {
          const existing = acc.find(x => x.name === t.attack_type);
          if (existing) existing.count++;
          else acc.push({ name: t.attack_type, count: 1 });
          return acc;
        }, []);

  // severity — use full aggregate from backend if available (covers ALL flows)
  const SEV_COLORS = {
    'Critical (5)': COLORS.critical,
    'High (4)':     COLORS.high,
    'Medium (3)':   COLORS.medium,
    'Low (≤2)':     COLORS.low,
  };
  const severityData = agg?.severity_dist
    ? Object.entries(agg.severity_dist)
        .map(([name, count]) => ({ name, count, color: SEV_COLORS[name] ?? '#9ca3af' }))
        .filter(d => d.count > 0)
    : [
        { name: 'Low',      count: threats.filter(t => t.severity <= 2).length,       color: COLORS.low },
        { name: 'Medium',   count: threats.filter(t => t.severity === 3).length,      color: COLORS.medium },
        { name: 'High',     count: threats.filter(t => t.severity === 4).length,      color: COLORS.high },
        { name: 'Critical', count: threats.filter(t => t.severity >= 5).length,       color: COLORS.critical },
      ].filter(d => d.count > 0);

  // protocol — use full aggregate from backend if available, otherwise fall back to 10 samples
  const protocolData = agg?.proto
    ? Object.entries(agg.proto).map(([name, value]) => ({ name: name.toUpperCase(), value }))
    : Object.entries(
        threats.reduce((acc, t) => {
          const proto = t.proto?.toLowerCase() ?? 'unknown';
          acc[proto] = (acc[proto] || 0) + 1;
          return acc;
        }, {})
      ).map(([name, value]) => ({ name: name.toUpperCase(), value }));

  // confidence — use full aggregate from backend if available, otherwise compute from 10 samples
  const confidenceData = agg?.confidence_dist
    ? Object.entries(agg.confidence_dist)
        .map(([range, count]) => ({ range, count }))
        .filter(d => d.count > 0)
    : (() => {
        const buckets = [
          { range: '50-70%', min: 0.50, max: 0.70 },
          { range: '70-80%', min: 0.70, max: 0.80 },
          { range: '80-90%', min: 0.80, max: 0.90 },
          { range: '90-95%', min: 0.90, max: 0.95 },
          { range: '95-99%', min: 0.95, max: 0.99 },
          { range: '99%+',   min: 0.99, max: 1.01 },
        ];
        return buckets
          .map(b => ({ range: b.range, count: threats.filter(t => t.confidence >= b.min && t.confidence < b.max).length }))
          .filter(d => d.count > 0);
      })();

  return (
    <>
      <div className="bg-grid"></div>
      <Header totalSamples={stateSource?.totalFlows ?? threats.length} />
      <div className="container">

        {/* summary line */}
        <div style={{
          fontFamily: 'IBM Plex Mono, monospace',
          fontSize: '0.8rem',
          color: 'var(--text-secondary)',
          marginBottom: '1.5rem',
          display: 'flex',
          gap: '2rem',
        }}>
          {maliciousCount != null && (
            <span>TOTAL MALICIOUS: <span style={{ color: 'var(--critical)' }}>{maliciousCount.toLocaleString()}</span></span>
          )}
          {avgConfidence != null && (
            <span>AVG CONFIDENCE: <span style={{ color: 'var(--accent-cyan)' }}>{avgConfidence}%</span></span>
          )}
          {threats.filter(t => t.summary).length > 0 && (
            <span>AI ANALYZED: <span style={{ color: 'var(--safe)' }}>{threats.filter(t => t.summary).length}</span></span>
          )}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', marginBottom: '2rem' }}>

          {/* Attack Type Distribution */}
          <div style={cardStyle}>
            <div style={titleStyle}>▶ Attack Type Distribution</div>
            {attackTypeCounts.length === 0 ? (
              <div style={{ color: 'var(--text-secondary)', fontFamily: 'IBM Plex Mono, monospace', fontSize: '0.8rem', textAlign: 'center', paddingTop: '4rem' }}>
                no threats analyzed yet — query the AI agent on the dashboard
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={attackTypeCounts} margin={{ left: 10, bottom: 60, top: 20 }}>
                  <XAxis
                    dataKey="name"
                    tick={{ fill: '#9ca3af', fontSize: 10, fontFamily: 'IBM Plex Mono' }}
                    angle={-40}
                    textAnchor="end"
                    interval={0}
                    tickFormatter={n => n
                      .replace('PartOfAHorizontalPortScan', 'HorizPortScan')
                      .replace('Distributed Denial of Service (DDoS)', 'DDoS')
                      .replace('-Attack', '-Atk')
                    }
                  />
                  <YAxis
                    tick={{ fill: '#9ca3af', fontSize: 11, fontFamily: 'IBM Plex Mono' }}
                    scale="log"
                    domain={[1, 'auto']}
                    allowDecimals={false}
                    tickFormatter={v => v >= 1000 ? `${(v/1000).toFixed(0)}k` : v}
                  />
                  <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: '#e5e7eb' }} labelStyle={{ color: '#00d9ff' }} cursor={{ fill: 'rgba(0,217,255,0.05)' }} />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {attackTypeCounts.map((entry, i) => (
                      <Cell key={i} fill={entry.name === 'Unanalyzed' ? '#4b5563' : '#00d9ff'} />
                    ))}
                    <LabelList dataKey="count" position="top" style={{ fill: '#9ca3af', fontSize: 10, fontFamily: 'IBM Plex Mono' }} formatter={v => v >= 1000 ? `${(v/1000).toFixed(1)}k` : v} />
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Severity Distribution */}
          <div style={cardStyle}>
            <div style={titleStyle}>▶ Severity Distribution</div>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={severityData} margin={{ left: 10, top: 20 }}>
                <XAxis dataKey="name" tick={{ fill: '#9ca3af', fontSize: 12, fontFamily: 'IBM Plex Mono' }} />
                <YAxis
                  tick={{ fill: '#9ca3af', fontSize: 12, fontFamily: 'IBM Plex Mono' }}
                  scale="log"
                  domain={[1, 'auto']}
                  allowDecimals={false}
                  tickFormatter={v => v >= 1000 ? `${(v/1000).toFixed(0)}k` : v}
                />
                <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: '#e5e7eb' }} labelStyle={{ color: '#00d9ff' }} cursor={{ fill: 'rgba(0,217,255,0.05)' }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                  <LabelList dataKey="count" position="top" style={{ fill: '#9ca3af', fontSize: 11, fontFamily: 'IBM Plex Mono' }} formatter={v => v >= 1000 ? `${(v/1000).toFixed(1)}k` : v} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Protocol Breakdown */}
          <div style={cardStyle}>
            <div style={titleStyle}>▶ Protocol Breakdown</div>
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={protocolData}
                  cx="50%" cy="50%"
                  outerRadius={90}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  labelLine={{ stroke: 'rgba(0,217,255,0.3)' }}
                >
                  {protocolData.map((entry, i) => (
                    <Cell key={i} fill={Object.values(COLORS)[i] || '#9ca3af'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
                <Legend wrapperStyle={{ fontFamily: 'IBM Plex Mono', fontSize: '0.8rem', color: '#9ca3af' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Model Confidence Distribution */}
          <div style={cardStyle}>
            <div style={titleStyle}>▶ Model Confidence Distribution</div>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={confidenceData} margin={{ left: 10, top: 20 }}>
                <XAxis dataKey="range" tick={{ fill: '#9ca3af', fontSize: 12, fontFamily: 'IBM Plex Mono' }} />
                <YAxis
                  tick={{ fill: '#9ca3af', fontSize: 12, fontFamily: 'IBM Plex Mono' }}
                  scale="log"
                  domain={[1, 'auto']}
                  allowDecimals={false}
                  tickFormatter={v => v >= 1000 ? `${(v/1000).toFixed(0)}k` : v}
                />
                <Tooltip contentStyle={tooltipStyle} itemStyle={{ color: '#e5e7eb' }} labelStyle={{ color: '#00d9ff' }} cursor={{ fill: 'rgba(0,217,255,0.05)' }} />
                <Bar dataKey="count" fill="#7c3aed" radius={[4, 4, 0, 0]}>
                  <LabelList dataKey="count" position="top" style={{ fill: '#9ca3af', fontSize: 11, fontFamily: 'IBM Plex Mono' }} formatter={v => v >= 1000 ? `${(v/1000).toFixed(1)}k` : v} />
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

        </div>
      </div>
    </>
  );
}
