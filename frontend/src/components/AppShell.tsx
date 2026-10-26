import { useState } from 'react'
import { NavLink } from 'react-router-dom'

const links = [
  { to: '/', label: 'Overview', end: true },
  { to: '/new-assessment', label: 'New assessment' },
  { to: '/recent', label: 'Recent' },
]

export function AppShell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false)

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <NavLink to="/" className="brand" aria-label="APIVigilante home">
          <span className="brand-mark" aria-hidden="true">
            AV
          </span>
          <span className="brand-copy">
            <span className="brand-name">APIVigilante</span>
            <span className="brand-tag">API security assessment</span>
          </span>
        </NavLink>
        <button
          className="nav-toggle"
          type="button"
          aria-expanded={open}
          aria-controls="primary-nav"
          onClick={() => setOpen((value) => !value)}
        >
          Menu
        </button>
        <nav id="primary-nav" className={open ? 'nav open' : 'nav'} aria-label="Primary">
          {links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.end}
              onClick={() => setOpen(false)}
            >
              {link.label}
            </NavLink>
          ))}
        </nav>
      </header>
      <main id="main" className="page">
        {children}
      </main>
      <footer className="footer">Assess only systems you are authorized to test. Active checks remain gated by the backend.</footer>
    </div>
  )
}
