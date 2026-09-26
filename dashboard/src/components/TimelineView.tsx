import { GitBranch } from 'lucide-react'

interface TimelineEvent {
  ts:      string
  source:  string
  event:   string
  details: string
  severity:'low'|'medium'|'high'
}

const DEMO_EVENTS: TimelineEvent[] = [
  { ts:'2026-09-25T08:01:00Z', source:'eventlog',  event:'Service installed',       details:'svchost.exe created new service "WinSec64"',         severity:'high'   },
  { ts:'2026-09-25T08:03:22Z', source:'registry',  event:'Run key modified',        details:'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', severity:'high'},
  { ts:'2026-09-25T08:05:10Z', source:'prefetch',  event:'Prefetch entry created',  details:'POWERSHELL.EXE-XXXXXXXX.pf',                          severity:'medium' },
  { ts:'2026-09-25T08:12:45Z', source:'shellbags', event:'Folder accessed',         details:'%AppData%\\Roaming\\Microsoft\\Windows\\Start Menu',    severity:'medium' },
  { ts:'2026-09-25T09:00:00Z', source:'eventlog',  event:'User logon',              details:'Account: DEMO-USER, Logon type: Interactive',          severity:'low'    },
  { ts:'2026-09-25T10:30:00Z', source:'mft',       event:'File created',            details:'C:\\Users\\DEMO-USER\\AppData\\Roaming\\update.exe',    severity:'high'   },
  { ts:'2026-09-25T10:32:00Z', source:'eventlog',  event:'Process created (4688)',  details:'Parent: explorer.exe → Child: update.exe',             severity:'high'   },
  { ts:'2026-09-25T10:35:00Z', source:'registry',  event:'Autorun registry write',  details:'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon', severity:'high'},
]

const SEV_COLORS: Record<string, string> = {
  low: 'badge-success', medium: 'badge-warning', high: 'badge-danger'
}

const SOURCE_ICONS: Record<string, string> = {
  eventlog:'📋', registry:'🗄️', prefetch:'⚡', shellbags:'📁', mft:'💾', browser:'🌐'
}

export function TimelineView() {
  return (
    <div style={{ height:'100%', overflowY:'auto' }}>
      <div className="page-header">
        <h1 className="page-title"><GitBranch size={20}/> Host Timeline</h1>
        <p className="page-subtitle">Correlating events across registry, eventlog, prefetch, shellbags and MFT</p>
      </div>

      <div className="timeline-wrap">
        {/* Host selector */}
        <div style={{ display:'flex', gap:10, alignItems:'center', marginBottom:24 }}>
          <select
            id="timeline-host-select"
            style={{
              background:'var(--bg-surface)', border:'1px solid var(--border)',
              borderRadius:'var(--radius)', color:'var(--text-primary)',
              padding:'8px 12px', fontSize:13, outline:'none'
            }}
          >
            <option>DEMO-HOST</option>
            <option>DESKTOP-WIN01</option>
          </select>
          <input
            type="date"
            id="timeline-from"
            defaultValue="2026-09-25"
            style={{
              background:'var(--bg-surface)', border:'1px solid var(--border)',
              borderRadius:'var(--radius)', color:'var(--text-primary)',
              padding:'8px 12px', fontSize:13, outline:'none'
            }}
          />
          <span style={{ color:'var(--text-muted)' }}>to</span>
          <input
            type="date"
            id="timeline-to"
            defaultValue="2026-09-26"
            style={{
              background:'var(--bg-surface)', border:'1px solid var(--border)',
              borderRadius:'var(--radius)', color:'var(--text-primary)',
              padding:'8px 12px', fontSize:13, outline:'none'
            }}
          />
        </div>

        {/* Events */}
        <div className="card" style={{ padding:'8px 20px' }}>
          {DEMO_EVENTS.map((ev, i) => (
            <div key={i} className="timeline-event" id={`timeline-event-${i}`}>
              <div className="timeline-dot" style={{
                borderColor: ev.severity === 'high' ? 'var(--danger)' :
                             ev.severity === 'medium' ? 'var(--warning)' : 'var(--success)'
              }}/>
              <div className="timeline-content">
                <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:4 }}>
                  <span className="timeline-ts">{new Date(ev.ts).toLocaleString()}</span>
                  <span className={`badge ${SEV_COLORS[ev.severity]}`}>{ev.severity}</span>
                  <span style={{ fontSize:12, color:'var(--text-secondary)' }}>
                    {SOURCE_ICONS[ev.source] || '📌'} {ev.source}
                  </span>
                </div>
                <div className="timeline-event-name">{ev.event}</div>
                <div className="timeline-details">{ev.details}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
