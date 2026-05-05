import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import API_URL from '../config';

export default function Home() {
  const navigate = useNavigate();
  const fileInputRef = useRef(null);
  const [status, setStatus] = useState('idle'); // idle | loading | error
  const [errorMsg, setErrorMsg] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const [steps, setSteps] = useState([]);
  const [liveTime, setLiveTime] = useState(0);

  // update timer while a step is running
  useEffect(() => {
    const activeStep = steps.find(s => s.active);
    if (!activeStep) return;
    const interval = setInterval(() => {
      setLiveTime(((Date.now() - activeStep.startedAt) / 1000).toFixed(1));
    }, 100);
    return () => clearInterval(interval);
  }, [steps]);

  async function handleFile(file) {
    if (!file) return;

    const ext = file.name.split('.').pop().toLowerCase();
    if (ext !== 'csv' && ext !== 'parquet') {
      setErrorMsg('Only .csv and .parquet files are supported.');
      setStatus('error');
      return;
    }

    setStatus('loading');
    setSteps([]);
    setErrorMsg('');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch(`${API_URL}/analyze`, {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || 'Server error');
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });

        // SSE chunks are separated by \n\n
        const parts = buffer.split('\n\n');
        buffer = parts.pop();

        for (const part of parts) {
          const line = part.trim();
          if (!line.startsWith('data: ')) continue;

          const data = JSON.parse(line.slice(6));

          if (data.type === 'step') {
            const now = Date.now();
            setSteps(prev => {
              const updated = prev.map(s =>
                s.active ? { ...s, active: false, done: true, elapsed: ((now - s.startedAt) / 1000).toFixed(1) } : s
              );
              return [...updated, { message: data.message, active: true, done: false, startedAt: now }];
            });
          } else if (data.type === 'result') {
            const now = Date.now();
            setSteps(prev => prev.map(s =>
              s.active ? { ...s, active: false, done: true, elapsed: ((now - s.startedAt) / 1000).toFixed(1) } : s
            ));
            const analysisState = {
              threats: data.threats,
              totalFlows: data.total_flows,
              maliciousCount: data.malicious_count,
              avgConfidence: data.avg_confidence,
              aggregates: data.aggregates,
            };
            localStorage.setItem('analysisResults', JSON.stringify(analysisState));
            sessionStorage.removeItem('demoMode');
            sessionStorage.removeItem('aiCache');
            navigate('/dashboard', { state: analysisState });
          } else if (data.type === 'error') {
            setErrorMsg(data.message);
            setStatus('error');
            setSteps(prev => prev.map(s => ({ ...s, active: false })));
          }
        }
      }
    } catch (err) {
      setErrorMsg(err.message);
      setStatus('error');
    }
  }

  function onFileChange(e) {
    handleFile(e.target.files[0]);
  }

  function onDrop(e) {
    e.preventDefault();
    setDragOver(false);
    handleFile(e.dataTransfer.files[0]);
  }

  return (
    <>
      <div className="bg-grid"></div>
      <header>
        <div className="logo">
          <div className="logo-icon">I</div>
          <h1>IoT-ThreatLens</h1>
        </div>
      </header>

      <div className="container" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '85vh' }}>
        <div style={{ textAlign: 'center', maxWidth: '600px', width: '100%' }}>

          {status !== 'loading' ? (
            <>
              <h2 style={{
                fontSize: '2rem', marginBottom: '1rem',
                background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-blue))',
                WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text'
              }}>
                IoT Network Threat Detection
              </h2>

              <p style={{ color: 'var(--text-secondary)', marginBottom: '2.5rem', lineHeight: '1.8' }}>
                Upload your network traffic data and let our XGBoost model identify malicious activity,
                powered by Gemini AI analysis.
              </p>

              <input
                ref={fileInputRef}
                type="file"
                accept=".csv,.parquet"
                style={{ display: 'none' }}
                onChange={onFileChange}
              />

              <div
                onClick={() => fileInputRef.current.click()}
                onDragOver={e => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={onDrop}
                style={{
                  border: `2px dashed ${dragOver ? 'var(--accent-cyan)' : 'var(--border)'}`,
                  borderRadius: '12px',
                  padding: '3rem',
                  marginBottom: '1.5rem',
                  cursor: 'pointer',
                  transition: 'all 0.3s ease',
                }}
                onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--accent-cyan)'}
                onMouseLeave={e => { if (!dragOver) e.currentTarget.style.borderColor = 'var(--border)'; }}
              >
                <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>📂</div>
                <p style={{ color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                  Click or drag a file to upload
                </p>
                <p style={{ color: 'var(--accent-cyan)', fontSize: '0.85rem', fontFamily: 'IBM Plex Mono, monospace' }}>
                  .parquet / .csv
                </p>
              </div>

              {status === 'error' && (
                <p style={{ color: 'var(--critical)', fontFamily: 'IBM Plex Mono, monospace', fontSize: '0.85rem', marginBottom: '1rem' }}>
                  ERROR: {errorMsg}
                </p>
              )}

              <button
                onClick={() => { sessionStorage.setItem('demoMode', 'true'); navigate('/dashboard', { state: { demo: true } }); }}
                style={{
                  background: 'transparent',
                  border: '1px solid var(--border)',
                  color: 'var(--text-secondary)',
                  padding: '0.75rem 2rem',
                  borderRadius: '8px',
                  fontSize: '0.85rem',
                  cursor: 'pointer',
                  letterSpacing: '1px',
                  fontFamily: 'IBM Plex Mono, monospace',
                  transition: 'all 0.2s ease',
                }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = 'var(--accent-cyan)'; e.currentTarget.style.color = 'var(--accent-cyan)'; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.color = 'var(--text-secondary)'; }}
              >
                VIEW DEMO DASHBOARD
              </button>
            </>
          ) : (
            <div style={{
              background: 'var(--surface)',
              border: '1px solid var(--border)',
              borderRadius: '12px',
              padding: '2.5rem',
              textAlign: 'left',
            }}>
              <p style={{
                fontFamily: 'IBM Plex Mono, monospace',
                color: 'var(--accent-cyan)',
                fontSize: '0.8rem',
                letterSpacing: '2px',
                marginBottom: '1.5rem',
              }}>
                ANALYZING TRAFFIC
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                {steps.map((step, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <span style={{
                      fontFamily: 'IBM Plex Mono, monospace',
                      fontSize: '1rem',
                      width: '1.2rem',
                      color: step.done ? 'var(--accent-cyan)' : 'var(--accent-blue)',
                    }}>
                      {step.done ? '✓' : '→'}
                    </span>
                    <span style={{
                      fontFamily: 'IBM Plex Mono, monospace',
                      fontSize: '0.85rem',
                      color: step.done ? 'var(--text-secondary)' : 'var(--text-primary)',
                      animation: step.active ? 'pulse 1.5s ease-in-out infinite' : 'none',
                      flex: 1,
                    }}>
                      {step.message}
                    </span>
                    <span style={{
                      fontFamily: 'IBM Plex Mono, monospace',
                      fontSize: '0.75rem',
                      color: 'var(--accent-cyan)',
                      opacity: step.active ? 1 : 0.6,
                      minWidth: '3rem',
                      textAlign: 'right',
                    }}>
                      {step.active ? `${liveTime}s` : step.elapsed != null ? `${step.elapsed}s` : ''}
                    </span>
                  </div>
                ))}

                {/* blinking cursor */}
                <div style={{
                  fontFamily: 'IBM Plex Mono, monospace',
                  fontSize: '0.85rem',
                  color: 'var(--accent-cyan)',
                  animation: 'blink 1s step-end infinite',
                }}>
                  _
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
