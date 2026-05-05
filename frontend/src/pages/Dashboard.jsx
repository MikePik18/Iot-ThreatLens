import { useState } from 'react';
import { useLocation } from 'react-router-dom';
import API_URL from '../config';
import Header from '../components/Header';
import StatsGrid from '../components/StatsGrid';
import ThreatFeed from '../components/ThreatFeed';
import ActivityMonitor from '../components/ActivityMonitor';
import ThreatModal from '../components/ThreatModal';
import mockThreats from '../data/mockThreats';

export default function Dashboard() {
  const location = useLocation();

  const isDemo = location.state?.demo === true || sessionStorage.getItem('demoMode') === 'true';
  const saved = isDemo ? null : JSON.parse(localStorage.getItem('analysisResults') || 'null');
  const stateSource = isDemo ? null : (location.state ?? saved);

  // if user uploaded a file use server mode, otherwise show demo data
  const useServer = !!stateSource;

  const [selectedThreat, setSelectedThreat] = useState(null);
  const [querying, setQuerying] = useState(false);
  // cache AI results in sessionStorage so they survive navigation within the same tab
  const [aiCache, setAiCache] = useState(() => {
    try { return JSON.parse(sessionStorage.getItem('aiCache') || '{}'); } catch { return {}; }
  });

  const threatKey = t => String(t.flow_id);

  function handleSelectThreat(threat) {
    const cached = aiCache[threatKey(threat)];
    setSelectedThreat(cached ? { ...threat, ...cached } : threat);
  }

  async function handleQueryAI() {
    if (!selectedThreat || querying) return;

    setQuerying(true);
    try {
      const res = await fetch(`${API_URL}/explain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          proto: selectedThreat.proto,
          service: selectedThreat.service,
          conn_state: selectedThreat.conn_state,
          confidence: selectedThreat.confidence,
          orig_bytes: selectedThreat.orig_bytes ?? -1,
          resp_bytes: selectedThreat.resp_bytes ?? -1,
          duration: selectedThreat.duration ?? -1,
          orig_pkts: selectedThreat.orig_pkts ?? -1,
          resp_pkts: selectedThreat.resp_pkts ?? -1,
          missed_bytes: selectedThreat.missed_bytes ?? -1,
        }),
      });

      const analysis = await res.json();
      // keep the original attack_type from the ML model, Gemini returns its own name
      const { attack_type: _ignored, ...aiFields } = analysis;
      const key = threatKey(selectedThreat);
      setAiCache(prev => {
        const updated = { ...prev, [key]: aiFields };
        sessionStorage.setItem('aiCache', JSON.stringify(updated));
        return updated;
      });
      setSelectedThreat(prev => ({ ...prev, ...aiFields }));
    } catch (err) {
      console.error('AI query failed:', err);
    } finally {
      setQuerying(false);
    }
  }

  // use mock data for stats in demo mode
  const statsThreats = useServer ? [] : mockThreats;

  return (
    <>
      <div className="bg-grid"></div>
      <Header totalSamples={stateSource?.totalFlows ?? mockThreats.length} />
      <div className="container">
        <StatsGrid
          threats={statsThreats}
          maliciousCount={stateSource?.maliciousCount}
          avgConfidence={stateSource?.avgConfidence}
          aggregates={stateSource?.aggregates}
        />
        <div className="dashboard-grid">
          <ThreatFeed useServer={useServer} onSelectThreat={handleSelectThreat} aiCache={aiCache} threatKey={threatKey} />
          <ActivityMonitor threats={statsThreats} maliciousCount={stateSource?.maliciousCount} aggregates={stateSource?.aggregates} avgConfidence={stateSource?.avgConfidence} />
        </div>
      </div>
      {selectedThreat && (
        <ThreatModal
          threat={selectedThreat}
          onClose={() => setSelectedThreat(null)}
          onQueryAI={handleQueryAI}
          querying={querying}
        />
      )}
    </>
  );
}
