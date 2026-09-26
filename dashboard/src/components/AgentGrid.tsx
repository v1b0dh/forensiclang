import { Monitor, Wifi, WifiOff, CheckCircle2, Clock } from 'lucide-react'
import { useAgentStore } from '../store/agentStore'

export function AgentGrid() {
  const { agents, selected, toggleAgent } = useAgentStore()
  const online  = agents.filter(a => a.online).length

  return (
    <div style={{ height: '100%', overflowY: 'auto' }}>
      {/* Header */}
      <div className="page-header">
        <h1 className="page-title"><Monitor size={20} /> Agent Overview</h1>
        <p className="page-subtitle">
          {online} online · {agents.length - online} offline · {selected.size} selected
        </p>
      </div>

      {/* Stat row */}
      <div className="card-grid card-grid-4" style={{ paddingBottom: 0 }}>
        <StatCard icon={<Monitor size={20}/>} cls="blue"   value={agents.length} label="Total Agents" />
        <StatCard icon={<Wifi    size={20}/>} cls="green"  value={online}         label="Online"       />
        <StatCard icon={<WifiOff size={20}/>} cls="red"    value={agents.length - online} label="Offline" />
        <StatCard icon={<CheckCircle2 size={20}/>} cls="purple" value={selected.size} label="Selected" />
      </div>

      {/* Agent cards */}
      <div className="agent-grid">
        {agents.map(agent => (
          <div
            key={agent.id}
            id={`agent-card-${agent.id}`}
            className={`agent-card ${selected.has(agent.id) ? 'selected' : ''}`}
            onClick={() => toggleAgent(agent.id)}
          >
            <div className="agent-header">
              <span className="agent-id">{agent.id}</span>
              <span className={`agent-status ${agent.online ? 'online' : 'offline'}`}>
                {agent.online ? <Wifi size={11}/> : <WifiOff size={11}/>}
                {agent.online ? 'Online' : 'Offline'}
              </span>
            </div>
            <div className="agent-meta">
              <span>🖥️ {agent.os} — {agent.hostname}</span>
              <span><Clock size={11} style={{display:'inline', marginRight:4}}/>
                {agent.online ? 'Connected now' : `Last: ${new Date(agent.lastSeen).toLocaleString()}`}
              </span>
              <span>📋 {agent.jobsRun} jobs executed</span>
            </div>
            {selected.has(agent.id) && (
              <div style={{marginTop:10}}>
                <span className="badge badge-info">✓ Selected</span>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function StatCard({ icon, cls, value, label }:
  { icon: React.ReactNode; cls: string; value: number; label: string }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${cls}`}>{icon}</div>
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </div>
  )
}
