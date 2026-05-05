import { NavLink } from 'react-router-dom';

export default function Navbar() {
  return (
    <nav style={{
      position: 'relative', zIndex: 100,
      background: 'rgba(10, 14, 26, 0.9)',
      borderBottom: '1px solid var(--border)',
      padding: '0 2rem',
      display: 'flex', gap: '0.5rem',
    }}>
      {[
        { to: '/dashboard', label: 'Dashboard' },
        { to: '/analytics', label: 'Analytics' },
      ].map(({ to, label }) => (
        <NavLink
          key={to}
          to={to}
          style={({ isActive }) => ({
            padding: '0.75rem 1.25rem',
            fontFamily: 'IBM Plex Mono, monospace',
            fontSize: '0.85rem',
            letterSpacing: '1px',
            textDecoration: 'none',
            borderBottom: isActive ? '2px solid var(--accent-cyan)' : '2px solid transparent',
            color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            transition: 'all 0.2s ease',
          })}
        >
          {label.toUpperCase()}
        </NavLink>
      ))}
    </nav>
  );
}
