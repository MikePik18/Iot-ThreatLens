import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import Navbar from './Navbar';

export default function Header({ totalSamples }) {
  const navigate = useNavigate();
  const [time, setTime] = useState('');

  useEffect(() => {
    const tick = () => setTime(new Date().toTimeString().split(' ')[0]);
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <>
      <header>
        <div className="logo" onClick={() => navigate('/')} style={{ cursor: 'pointer' }}>
          <div className="logo-icon">I</div>
          <h1>IoT-ThreatLens</h1>
        </div>
        <div className="status-bar">
          <div className="status-item">
            <span className="status-dot active"></span>
            <span>SYSTEM ACTIVE</span>
          </div>
          <div className="status-item">
            <span>ANALYZED: {totalSamples} FLOWS</span>
          </div>
          <div className="status-item">
            <span>{time}</span>
          </div>
        </div>
      </header>
      <Navbar />
    </>
  );
}
