import { create } from 'zustand'

export interface Agent {
  id:         string
  online:     boolean
  os:         string
  hostname:   string
  lastSeen:   string
  jobsRun:    number
}

interface AgentState {
  agents: Agent[]
  selected: Set<string>
  setAgents:   (agents: Agent[]) => void
  toggleAgent: (id: string) => void
  clearSelected: () => void
}

export const useAgentStore = create<AgentState>((set) => ({
  agents: [
    // Demo data — replaced by live API in production
    { id: 'WIN-DEMO-01',  online: true,  os: 'Windows 11', hostname: 'DESKTOP-WIN01', lastSeen: new Date().toISOString(), jobsRun: 12 },
    { id: 'WIN-DEMO-02',  online: true,  os: 'Windows 10', hostname: 'SERVER-DC01',   lastSeen: new Date().toISOString(), jobsRun: 7  },
    { id: 'LNX-DEMO-01',  online: false, os: 'Ubuntu 22',  hostname: 'ubuntu-lab',    lastSeen: '2026-09-25T14:30:00Z',  jobsRun: 3  },
    { id: 'LNX-DEMO-02',  online: true,  os: 'Kali Linux', hostname: 'kali-analyst',  lastSeen: new Date().toISOString(), jobsRun: 21 },
  ],
  selected: new Set(),
  setAgents:   (agents) => set({ agents }),
  toggleAgent: (id) => set(state => {
    const next = new Set(state.selected)
    next.has(id) ? next.delete(id) : next.add(id)
    return { selected: next }
  }),
  clearSelected: () => set({ selected: new Set() }),
}))
