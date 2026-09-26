import { useState, useRef } from 'react'
import { Play, Users, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react'
import { useAgentStore } from '../store/agentStore'

const EXAMPLE_SCRIPT = `// Live demo: detect persistence mechanism on a host

scan processes
  filter by parent_pid == 1

collect memory from pid 4512
  filter by region [heap]
  export to artifact "suspicious_heap"

collect disk
  from host "DEMO-HOST"
  filter by path contains "AppData"
  export to artifact "startup_items"

timeline host "DEMO-HOST"
  from "2026-09-20" to "2026-09-25"
  include [registry, eventlog, prefetch, shellbags]
  output report "persistence_analysis.html"

correlate "suspicious_heap" with "known_malware.ioc"
  flag anomalies

report "persistence_analysis" as "final_report"
  format html`

type JobStatus = 'idle' | 'running' | 'success' | 'error'

export function ScriptEditor() {
  const [script, setScript]   = useState(EXAMPLE_SCRIPT)
  const [jobId, setJobId]     = useState<string | null>(null)
  const [jobStatus, setJobStatus] = useState<JobStatus>('idle')
  const [log, setLog]         = useState<string[]>([])
  const { agents, selected }  = useAgentStore()
  const textareaRef           = useRef<HTMLTextAreaElement>(null)

  const selectedAgents = agents.filter(a => selected.has(a.id))

  async function deployScript() {
    if (selectedAgents.length === 0) {
      alert('Select at least one agent from the Agents view.')
      return
    }
    setJobStatus('running')
    setLog([`[${new Date().toISOString()}] Deploying to ${selectedAgents.length} agents...`])

    try {
      const res = await fetch('/api/jobs', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${import.meta.env.VITE_API_TOKEN || 'dev-secret-change-me'}`,
        },
        body: JSON.stringify({
          script_code: script,
          targets: [...selected],
        }),
      })

      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setJobId(data.job_id)
      setLog(prev => [
        ...prev,
        `[${new Date().toISOString()}] Job ID: ${data.job_id}`,
        `[${new Date().toISOString()}] Dispatched to: ${data.dispatched.join(', ') || 'none'}`,
        data.missed?.length ? `[WARN] Offline agents missed: ${data.missed.join(', ')}` : '',
      ].filter(Boolean))
      setJobStatus('success')
    } catch (err) {
      setLog(prev => [...prev, `[ERROR] ${String(err)}`])
      setJobStatus('error')
    }
  }

  // Tab key inserts 2 spaces
  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === 'Tab') {
      e.preventDefault()
      const ta = textareaRef.current!
      const start = ta.selectionStart
      const end   = ta.selectionEnd
      const newVal = ta.value.substring(0, start) + '  ' + ta.value.substring(end)
      setScript(newVal)
      requestAnimationFrame(() => {
        ta.selectionStart = ta.selectionEnd = start + 2
      })
    }
  }

  return (
    <div className="editor-panel">
      {/* Toolbar */}
      <div className="editor-toolbar">
        <h2 style={{ fontWeight: 700, fontSize: 15, flexShrink: 0 }}>JOCKY Script Editor</h2>

        <div style={{ display:'flex', alignItems:'center', gap:8, marginLeft:'auto' }}>
          <span style={{ color:'var(--text-secondary)', fontSize:12 }}>
            <Users size={13} style={{display:'inline', marginRight:4}}/>
            {selectedAgents.length} agent{selectedAgents.length !== 1 ? 's' : ''} selected
          </span>
          <button
            id="btn-deploy"
            className="btn btn-primary"
            onClick={deployScript}
            disabled={jobStatus === 'running'}
          >
            {jobStatus === 'running'
              ? <><span className="spinner"/>&nbsp;Deploying…</>
              : <><Play size={14}/> Deploy</>
            }
          </button>
        </div>
      </div>

      <div className="editor-wrap">
        {/* Code area */}
        <textarea
          id="jocky-code-editor"
          ref={textareaRef}
          className="code-editor"
          value={script}
          onChange={e => setScript(e.target.value)}
          onKeyDown={handleKeyDown}
          spellCheck={false}
          placeholder="// Write your JOCKY forensic script here…"
        />

        {/* Output panel */}
        <div className="editor-output">
          <p style={{ fontWeight:600, marginBottom:12, color:'var(--text-secondary)', fontSize:12, textTransform:'uppercase', letterSpacing:'0.5px' }}>
            Output Log
          </p>

          {jobStatus === 'idle' && (
            <div className="empty-state" style={{ padding:'30px 0' }}>
              <Play size={28}/>
              <p style={{ marginTop:8, fontSize:12 }}>Deploy a script to see output</p>
            </div>
          )}

          {log.map((line, i) => (
            <div key={i} className="job-panel" style={{ marginBottom:6, padding:'8px 12px' }}>
              <span style={{ fontFamily:'var(--font-mono)', fontSize:11 }}>{line}</span>
            </div>
          ))}

          {jobStatus === 'success' && jobId && (
            <div style={{ marginTop:12 }}>
              <div style={{ display:'flex', alignItems:'center', gap:6, color:'var(--success)', marginBottom:8 }}>
                <CheckCircle2 size={14}/> Job queued successfully
              </div>
              <div style={{ fontSize:11, color:'var(--text-muted)' }}>
                Job ID: <span style={{ fontFamily:'var(--font-mono)', color:'var(--accent)' }}>{jobId}</span>
              </div>
            </div>
          )}

          {jobStatus === 'error' && (
            <div style={{ display:'flex', alignItems:'center', gap:6, color:'var(--danger)', marginTop:12 }}>
              <AlertCircle size={14}/> Deployment failed
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
