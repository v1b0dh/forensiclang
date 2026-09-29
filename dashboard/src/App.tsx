import { useState } from 'react'
import {
  Server, Terminal, Archive, GitBranch, ShieldAlert,
  Activity, Disc3, Flame, type LucideIcon
} from 'lucide-react'
import { AgentGrid }          from './components/AgentGrid'
import { ScriptEditor }       from './components/ScriptEditor'
import { ArtifactViewer }     from './components/ArtifactViewer'
import { TimelineView }       from './components/TimelineView'
import { IOCCorrelation }     from './components/IOCCorrelation'
import { CarvingWorkbench }   from './components/CarvingWorkbench'
import { SanitizationCenter } from './components/SanitizationCenter'
import { useAgentStore }      from './store/agentStore'

type View = 'agents' | 'editor' | 'artifacts' | 'timeline' | 'ioc' | 'carver' | 'sanitizer'

const NAV_ITEMS: { id: View; label: string; icon: LucideIcon }[] = [
  { id: 'agents',    label: 'Agents',      icon: Server      },
  { id: 'editor',    label: 'Editor',      icon: Terminal    },
  { id: 'carver',    label: 'File Carver', icon: Disc3       },
  { id: 'sanitizer', label: 'Sanitizer',   icon: Flame       },
  { id: 'artifacts', label: 'Artifacts',   icon: Archive     },
  { id: 'timeline',  label: 'Timeline',    icon: GitBranch   },
  { id: 'ioc',       label: 'IOC Match',   icon: ShieldAlert },
]

export function App() {
  const [view, setView] = useState<View>('agents')
  const onlineCount = useAgentStore(s => s.agents.filter(a => a.online).length)

  return (
    <div className="app">
      {/* ── Sidebar ─────────────────────────────────────────── */}
      <nav className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-icon">🔬</div>
          <span className="logo-text">JOCKY</span>
        </div>

        {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            id={`nav-${id}`}
            className={`nav-item ${view === id ? 'active' : ''}`}
            onClick={() => setView(id)}
          >
            <Icon size={16} />
            {label}
          </button>
        ))}

        <div className="sidebar-footer">
          <div className="status-badge">
            <Activity size={12} />
            <div className="status-dot" />
            {onlineCount} agent{onlineCount !== 1 ? 's' : ''} online
          </div>
        </div>
      </nav>

      {/* ── Main ─────────────────────────────────────────────── */}
      <main id="main-content">
        {view === 'agents'    && <AgentGrid />}
        {view === 'editor'    && <ScriptEditor />}
        {view === 'carver'    && <CarvingWorkbench />}
        {view === 'sanitizer' && <SanitizationCenter />}
        {view === 'artifacts' && <ArtifactViewer />}
        {view === 'timeline'  && <TimelineView />}
        {view === 'ioc'       && <IOCCorrelation />}
      </main>
    </div>
  )
}
