import { useState } from 'react'
import { Archive, Download, Eye, Search } from 'lucide-react'

interface Artifact {
  id:         string
  name:       string
  size:       number
  job_id:     string
  agent_id:   string
  created_at: string
  type:       'memory' | 'disk' | 'network' | 'registry'
}

const DEMO_ARTIFACTS: Artifact[] = [
  { id:'a1', name:'suspicious_heap_1727368800.jkya',  size:4_194_304,  job_id:'job-001', agent_id:'WIN-DEMO-01', created_at:'2026-09-26T10:00:00Z', type:'memory' },
  { id:'a2', name:'startup_items_1727368802.jkya',    size:102_400,     job_id:'job-001', agent_id:'WIN-DEMO-01', created_at:'2026-09-26T10:00:02Z', type:'disk'   },
  { id:'a3', name:'network_capture_1727368900.jkya',  size:8_388_608,  job_id:'job-002', agent_id:'WIN-DEMO-02', created_at:'2026-09-26T10:15:00Z', type:'network' },
  { id:'a4', name:'registry_run_1727369000.jkya',     size:65_536,      job_id:'job-003', agent_id:'LNX-DEMO-02', created_at:'2026-09-26T10:30:00Z', type:'registry'}
]

const TYPE_COLORS: Record<string, string> = {
  memory: 'badge-info', disk: 'badge-warning', network: 'badge-danger', registry: 'badge-success'
}

function fmtBytes(n: number) {
  if (n > 1_000_000) return `${(n/1_048_576).toFixed(1)} MB`
  if (n > 1_000)     return `${(n/1_024).toFixed(1)} KB`
  return `${n} B`
}

export function ArtifactViewer() {
  const [query, setQuery] = useState('')
  const filtered = DEMO_ARTIFACTS.filter(a =>
    a.name.toLowerCase().includes(query.toLowerCase()) ||
    a.agent_id.toLowerCase().includes(query.toLowerCase())
  )

  return (
    <div style={{ height:'100%', overflowY:'auto' }}>
      <div className="page-header">
        <h1 className="page-title"><Archive size={20}/> Artifact Store</h1>
        <p className="page-subtitle">Collected forensic artefacts — read-only, tamper-evident JKYA format</p>
      </div>

      {/* Search */}
      <div style={{ padding:'16px 28px 0', display:'flex', gap:10 }}>
        <div style={{ position:'relative', flex:1, maxWidth:400 }}>
          <Search size={14} style={{ position:'absolute', left:12, top:'50%', transform:'translateY(-50%)', color:'var(--text-muted)' }}/>
          <input
            id="artifact-search"
            style={{
              width:'100%', padding:'8px 12px 8px 36px',
              background:'var(--bg-surface)', border:'1px solid var(--border)',
              borderRadius:'var(--radius)', color:'var(--text-primary)',
              fontSize:13, outline:'none'
            }}
            placeholder="Search artifacts…"
            value={query}
            onChange={e => setQuery(e.target.value)}
          />
        </div>
      </div>

      {/* Table */}
      <div className="data-table-wrap" style={{ paddingTop:20 }}>
        <div className="card" style={{ padding:0, overflow:'hidden' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Size</th>
                <th>Agent</th>
                <th>Job</th>
                <th>Collected</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ textAlign:'center', padding:40, color:'var(--text-muted)' }}>
                    No artifacts found
                  </td>
                </tr>
              )}
              {filtered.map(a => (
                <tr key={a.id} id={`artifact-row-${a.id}`}>
                  <td className="mono">{a.name}</td>
                  <td><span className={`badge ${TYPE_COLORS[a.type]}`}>{a.type}</span></td>
                  <td>{fmtBytes(a.size)}</td>
                  <td className="mono">{a.agent_id}</td>
                  <td className="mono" style={{ color:'var(--accent)', fontSize:11 }}>{a.job_id}</td>
                  <td style={{ color:'var(--text-secondary)', fontSize:12 }}>
                    {new Date(a.created_at).toLocaleString()}
                  </td>
                  <td>
                    <div style={{ display:'flex', gap:6 }}>
                      <button className="btn btn-ghost" style={{ padding:'4px 10px' }}>
                        <Eye size={12}/> View
                      </button>
                      <button className="btn btn-ghost" style={{ padding:'4px 10px' }}>
                        <Download size={12}/> Export
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
