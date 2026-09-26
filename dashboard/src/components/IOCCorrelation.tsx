import { useState } from 'react'
import { ShieldAlert, Plus, X, Search } from 'lucide-react'

const DEFAULT_IOCS = [
  'c2e24e8c5a3c7d1a2f9b8e4d6f2a1c3b',     // MD5 hash (demo)
  '185.234.218.95',                           // C2 IP
  'winsec64.exe',                              // Malware filename
  'HKLM\\SOFTWARE\\WinSec64',                // Registry key
  'update.exe',                                // Suspicious process
  '*.onion',                                   // Tor pattern
]

const MATCHES = [
  { artifact:'suspicious_heap', ioc:'winsec64.exe', confidence:92, type:'filename' },
  { artifact:'suspicious_heap', ioc:'185.234.218.95', confidence:78, type:'network_ioc' },
  { artifact:'registry_run',   ioc:'HKLM\\SOFTWARE\\WinSec64', confidence:99, type:'registry_key' },
]

export function IOCCorrelation() {
  const [iocs, setIocs] = useState<string[]>(DEFAULT_IOCS)
  const [newIoc, setNewIoc] = useState('')

  function addIoc() {
    const trimmed = newIoc.trim()
    if (trimmed && !iocs.includes(trimmed)) {
      setIocs(prev => [...prev, trimmed])
      setNewIoc('')
    }
  }

  return (
    <div style={{ height:'100%', overflowY:'auto' }}>
      <div className="page-header">
        <h1 className="page-title"><ShieldAlert size={20}/> IOC Correlation</h1>
        <p className="page-subtitle">Match collected artifacts against known Indicators of Compromise</p>
      </div>

      <div className="card-grid card-grid-2" style={{ alignItems:'start' }}>
        {/* IOC list */}
        <div className="card">
          <h3 style={{ fontWeight:600, marginBottom:12 }}>IOC List</h3>
          <div style={{ display:'flex', gap:8, marginBottom:12 }}>
            <input
              id="ioc-input"
              style={{
                flex:1, padding:'8px 12px',
                background:'var(--bg-base)', border:'1px solid var(--border)',
                borderRadius:'var(--radius)', color:'var(--text-primary)',
                fontSize:13, outline:'none', fontFamily:'var(--font-mono)'
              }}
              placeholder="Add IP, hash, filename, regex…"
              value={newIoc}
              onChange={e => setNewIoc(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addIoc()}
            />
            <button id="btn-add-ioc" className="btn btn-primary" onClick={addIoc}>
              <Plus size={14}/>
            </button>
          </div>
          <div style={{ display:'flex', flexWrap:'wrap', gap:4 }}>
            {iocs.map(ioc => (
              <span key={ioc} className="ioc-tag" style={{ display:'inline-flex', alignItems:'center', gap:4 }}>
                {ioc}
                <X size={10} style={{ cursor:'pointer', opacity:0.7 }}
                   onClick={() => setIocs(prev => prev.filter(i => i !== ioc))}/>
              </span>
            ))}
          </div>
          <div style={{ marginTop:16 }}>
            <button id="btn-run-correlation" className="btn btn-primary" style={{ width:'100%' }}>
              <Search size={14}/> Run Correlation
            </button>
          </div>
        </div>

        {/* Matches */}
        <div className="card">
          <h3 style={{ fontWeight:600, marginBottom:12 }}>
            Matches <span className="badge badge-danger" style={{ marginLeft:8 }}>{MATCHES.length} hits</span>
          </h3>
          {MATCHES.map((m, i) => (
            <div key={i} id={`ioc-match-${i}`} style={{
              padding:'12px 14px',
              background:'var(--bg-elevated)',
              border:'1px solid rgba(239,68,68,0.2)',
              borderRadius:'var(--radius)',
              marginBottom:10
            }}>
              <div style={{ display:'flex', justifyContent:'space-between', marginBottom:6 }}>
                <span style={{ fontWeight:600, color:'var(--danger)' }}>🚨 {m.ioc}</span>
                <span className="badge badge-danger">{m.confidence}% match</span>
              </div>
              <div style={{ fontSize:12, color:'var(--text-secondary)' }}>
                Artifact: <span className="mono" style={{ color:'var(--accent)' }}>{m.artifact}</span>
                &nbsp;·&nbsp; Type: <span>{m.type}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
