import React, { useState } from 'react'
import {
  Crosshair,
  ShieldAlert,
  Clock,
  Cpu,
  Layers,
  Search,
  AlertTriangle,
  CheckCircle2,
  Play,
  FileCode,
  Terminal,
  Activity,
  Bug,
  RefreshCw,
  ExternalLink,
  ChevronRight
} from 'lucide-react'

interface TimestompAnomaly {
  file_path: string
  anomaly_type: string
  severity: string
  mitre_attack: string
  si_created: string
  fn_created: string
  delta_seconds: number
  description: string
}

interface AlternateDataStream {
  parent_file: string
  stream_name: string
  size_bytes: number
  is_suspicious: boolean
  threat_tags: string[]
  mitre_attack: string
}

interface AntiForensicsReport {
  status: string
  target_path: string
  scanned_at: string
  total_files_scanned: number
  evasion_detected: boolean
  timestomp_anomalies: TimestompAnomaly[]
  alternate_data_streams: AlternateDataStream[]
}

interface InjectedRegion {
  pid: number
  process_name: string
  base_address: string
  region_size: number
  protection: string
  memory_type: string
  entropy: number
  severity: string
  indicators: string[]
  mitre_attack: string
  hex_preview: string
  description: string
}

interface MemoryInjectionReport {
  status: string
  scanned_at: string
  total_processes_scanned: number
  suspicious_regions_found: number
  critical_injections_found: number
  regions: InjectedRegion[]
}

export function ThreatHunter() {
  const [activeTab, setActiveTab] = useState<'antiforensics' | 'memory'>('antiforensics')

  // Anti-Forensics State
  const [targetPath, setTargetPath] = useState('')
  const [afReport, setAfReport] = useState<AntiForensicsReport | null>(null)
  const [afLoading, setAfLoading] = useState(false)
  const [afError, setAfError] = useState<string | null>(null)

  // Memory Hunter State
  const [targetPid, setTargetPid] = useState('')
  const [memReport, setMemReport] = useState<MemoryInjectionReport | null>(null)
  const [memLoading, setMemLoading] = useState(false)
  const [memError, setMemError] = useState<string | null>(null)

  // Run Anti-Forensics Scan
  const runAntiForensicsScan = async (simulate: boolean = false) => {
    try {
      setAfLoading(true)
      setAfError(null)
      const res = await fetch('/api/forensics/antiforensics/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_path: targetPath.trim() || undefined,
          simulate_test: simulate,
          recursive: false,
        }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data: AntiForensicsReport = await res.json()
      setAfReport(data)
    } catch (e: any) {
      setAfError(e.message || 'Anti-forensics scan failed')
    } finally {
      setAfLoading(false)
    }
  }

  // Run Memory Injection Scan
  const runMemoryScan = async (simulate: boolean = false) => {
    try {
      setMemLoading(true)
      setMemError(null)
      const pidVal = targetPid.trim() ? parseInt(targetPid.trim(), 10) : undefined
      const res = await fetch('/api/forensics/memory/injection-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pid: pidVal,
          simulate_injection: simulate,
        }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data: MemoryInjectionReport = await res.json()
      setMemReport(data)
    } catch (e: any) {
      setMemError(e.message || 'Memory injection scan failed')
    } finally {
      setMemLoading(false)
    }
  }

  return (
    <div style={{ padding: '24px', maxWidth: '1400px', margin: '0 auto', color: 'var(--text)' }}>
      {/* ── Header ────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '10px', margin: 0 }}>
            <Crosshair size={28} color="#ef4444" />
            Advanced Threat & Evasion Hunter
          </h1>
          <p style={{ margin: '6px 0 0 0', color: 'var(--text-muted)', fontSize: '13px' }}>
            Non-invasive live forensics: NTFS Timestomping delta analysis, Alternate Data Streams, and Reflective Memory Injection detection.
          </p>
        </div>

        {/* Tab Switcher */}
        <div style={{ display: 'flex', gap: '8px', background: 'var(--bg-card)', padding: '4px', borderRadius: '8px', border: '1px solid var(--border)' }}>
          <button
            onClick={() => setActiveTab('antiforensics')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 16px',
              borderRadius: '6px',
              border: 'none',
              background: activeTab === 'antiforensics' ? '#ef4444' : 'transparent',
              color: activeTab === 'antiforensics' ? '#fff' : 'var(--text-muted)',
              fontWeight: 600,
              fontSize: '13px',
              cursor: 'pointer',
            }}
          >
            <Clock size={16} />
            Anti-Forensics & ADS
          </button>
          <button
            onClick={() => setActiveTab('memory')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              padding: '8px 16px',
              borderRadius: '6px',
              border: 'none',
              background: activeTab === 'memory' ? '#8b5cf6' : 'transparent',
              color: activeTab === 'memory' ? '#fff' : 'var(--text-muted)',
              fontWeight: 600,
              fontSize: '13px',
              cursor: 'pointer',
            }}
          >
            <Cpu size={16} />
            Memory Injection (RWX)
          </button>
        </div>
      </div>

      {/* ────────────────────────────────────────────────────────
          TAB 1: ANTI-FORENSICS & TIMESTOMPING
      ──────────────────────────────────────────────────────── */}
      {activeTab === 'antiforensics' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Controls Bar */}
          <div style={{ background: 'var(--bg-card)', padding: '18px', borderRadius: '10px', border: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: '300px' }}>
                <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px', fontWeight: 600 }}>
                  Audit Target Directory / File
                </label>
                <input
                  type="text"
                  placeholder="e.g. C:\Windows\System32 or leave blank for temp workspace"
                  value={targetPath}
                  onChange={(e) => setTargetPath(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '9px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--border)',
                    background: 'var(--bg-input)',
                    color: 'var(--text)',
                    fontSize: '13px',
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-end', paddingTop: '18px' }}>
                <button
                  onClick={() => runAntiForensicsScan(false)}
                  disabled={afLoading}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '9px 18px',
                    borderRadius: '6px',
                    background: '#ef4444',
                    color: '#fff',
                    border: 'none',
                    fontWeight: 600,
                    fontSize: '13px',
                    cursor: afLoading ? 'not-allowed' : 'pointer',
                  }}
                >
                  {afLoading ? <RefreshCw size={15} className="spin" /> : <Search size={15} />}
                  Run Live Audit
                </button>

                <button
                  onClick={() => runAntiForensicsScan(true)}
                  disabled={afLoading}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '9px 16px',
                    borderRadius: '6px',
                    background: 'rgba(239, 68, 68, 0.15)',
                    color: '#f87171',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    fontWeight: 600,
                    fontSize: '13px',
                    cursor: afLoading ? 'not-allowed' : 'pointer',
                  }}
                >
                  <Bug size={15} />
                  Simulate Evasion Attack (SIH Demo)
                </button>
              </div>
            </div>

            {afError && (
              <div style={{ marginTop: '14px', padding: '10px 14px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '6px', color: '#f87171', fontSize: '13px' }}>
                Error: {afError}
              </div>
            )}
          </div>

          {/* Results Display */}
          {afReport && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {/* Summary Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
                <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Files Scanned</div>
                  <div style={{ fontSize: '22px', fontWeight: 700, marginTop: '4px' }}>{afReport.total_files_scanned}</div>
                </div>

                <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Timestomp Anomalies</div>
                  <div style={{ fontSize: '22px', fontWeight: 700, marginTop: '4px', color: afReport.timestomp_anomalies.length > 0 ? '#ef4444' : '#10b981' }}>
                    {afReport.timestomp_anomalies.length}
                  </div>
                </div>

                <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Alternate Data Streams</div>
                  <div style={{ fontSize: '22px', fontWeight: 700, marginTop: '4px', color: afReport.alternate_data_streams.length > 0 ? '#f59e0b' : 'var(--text)' }}>
                    {afReport.alternate_data_streams.length}
                  </div>
                </div>

                <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Evasion Status</div>
                  <div style={{ fontSize: '14px', fontWeight: 700, marginTop: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    {afReport.evasion_detected ? (
                      <span style={{ color: '#ef4444', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <AlertTriangle size={16} /> EVASION DETECTED
                      </span>
                    ) : (
                      <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <CheckCircle2 size={16} /> CLEAN
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Timestomp Anomalies Table */}
              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border)', overflow: 'hidden' }}>
                <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontWeight: 600, fontSize: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Clock size={16} color="#ef4444" />
                    NTFS Timestomping Findings (MITRE ATT&CK T1070.006)
                  </div>
                  <span style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '12px', background: 'rgba(239,68,68,0.15)', color: '#f87171', fontWeight: 600 }}>
                    {afReport.timestomp_anomalies.length} Detected
                  </span>
                </div>

                {afReport.timestomp_anomalies.length === 0 ? (
                  <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                    No timestomping or timestamp inversion anomalies detected in target path.
                  </div>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                      <thead>
                        <tr style={{ background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-muted)' }}>
                          <th style={{ padding: '10px 14px' }}>Target File</th>
                          <th style={{ padding: '10px 14px' }}>Technique</th>
                          <th style={{ padding: '10px 14px' }}>Severity</th>
                          <th style={{ padding: '10px 14px' }}>$STANDARD_INFO</th>
                          <th style={{ padding: '10px 14px' }}>$FILE_NAME</th>
                          <th style={{ padding: '10px 14px' }}>Delta</th>
                          <th style={{ padding: '10px 14px' }}>Forensic Indicator</th>
                        </tr>
                      </thead>
                      <tbody>
                        {afReport.timestomp_anomalies.map((anom, idx) => (
                          <tr key={idx} style={{ borderBottom: '1px solid var(--border)', background: anom.severity === 'CRITICAL' ? 'rgba(239,68,68,0.04)' : 'transparent' }}>
                            <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: 600, color: 'var(--text)' }}>
                              {anom.file_path}
                            </td>
                            <td style={{ padding: '10px 14px' }}>
                              <span style={{ background: 'rgba(255,255,255,0.08)', padding: '2px 6px', borderRadius: '4px', fontFamily: 'monospace', fontSize: '11px' }}>
                                {anom.mitre_attack}
                              </span>
                            </td>
                            <td style={{ padding: '10px 14px' }}>
                              <span style={{
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '11px',
                                fontWeight: 700,
                                background: anom.severity === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : 'rgba(245,158,11,0.2)',
                                color: anom.severity === 'CRITICAL' ? '#f87171' : '#fbbf24',
                              }}>
                                {anom.severity}
                              </span>
                            </td>
                            <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: 'var(--text-muted)' }}>{anom.si_created}</td>
                            <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: 'var(--text-muted)' }}>{anom.fn_created}</td>
                            <td style={{ padding: '10px 14px', fontFamily: 'monospace', color: '#f87171', fontWeight: 600 }}>
                              {anom.delta_seconds > 0 ? `${anom.delta_seconds.toFixed(0)}s` : '0s'}
                            </td>
                            <td style={{ padding: '10px 14px', color: 'var(--text-muted)' }}>{anom.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Alternate Data Streams Table */}
              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border)', overflow: 'hidden' }}>
                <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontWeight: 600, fontSize: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Layers size={16} color="#f59e0b" />
                    NTFS Alternate Data Streams (MITRE ATT&CK T1564.004)
                  </div>
                  <span style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '12px', background: 'rgba(245,158,11,0.15)', color: '#fbbf24', fontWeight: 600 }}>
                    {afReport.alternate_data_streams.length} Streams Found
                  </span>
                </div>

                {afReport.alternate_data_streams.length === 0 ? (
                  <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                    No hidden Alternate Data Streams detected.
                  </div>
                ) : (
                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
                      <thead>
                        <tr style={{ background: 'rgba(255,255,255,0.02)', borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-muted)' }}>
                          <th style={{ padding: '10px 14px' }}>Host File</th>
                          <th style={{ padding: '10px 14px' }}>Hidden Stream Name</th>
                          <th style={{ padding: '10px 14px' }}>Size</th>
                          <th style={{ padding: '10px 14px' }}>Status</th>
                          <th style={{ padding: '10px 14px' }}>Threat Tags</th>
                          <th style={{ padding: '10px 14px' }}>MITRE</th>
                        </tr>
                      </thead>
                      <tbody>
                        {afReport.alternate_data_streams.map((ads, idx) => (
                          <tr key={idx} style={{ borderBottom: '1px solid var(--border)' }}>
                            <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{ads.parent_file}</td>
                            <td style={{ padding: '10px 14px', fontFamily: 'monospace', fontWeight: 600, color: ads.is_suspicious ? '#ef4444' : '#38bdf8' }}>
                              {ads.stream_name}
                            </td>
                            <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{ads.size_bytes} B</td>
                            <td style={{ padding: '10px 14px' }}>
                              <span style={{
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '11px',
                                fontWeight: 700,
                                background: ads.is_suspicious ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)',
                                color: ads.is_suspicious ? '#f87171' : '#10b981',
                              }}>
                                {ads.is_suspicious ? 'SUSPICIOUS' : 'BENIGN'}
                              </span>
                            </td>
                            <td style={{ padding: '10px 14px' }}>
                              <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                                {ads.threat_tags.map((t, ti) => (
                                  <span key={ti} style={{ padding: '1px 6px', background: 'rgba(239,68,68,0.15)', color: '#f87171', borderRadius: '4px', fontSize: '10px', fontWeight: 600 }}>
                                    {t}
                                  </span>
                                ))}
                              </div>
                            </td>
                            <td style={{ padding: '10px 14px', fontFamily: 'monospace' }}>{ads.mitre_attack}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ────────────────────────────────────────────────────────
          TAB 2: REFLECTIVE MEMORY INJECTION HUNTER
      ──────────────────────────────────────────────────────── */}
      {activeTab === 'memory' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          {/* Controls Bar */}
          <div style={{ background: 'var(--bg-card)', padding: '18px', borderRadius: '10px', border: '1px solid var(--border)' }}>
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
              <div style={{ width: '220px' }}>
                <label style={{ display: 'block', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px', fontWeight: 600 }}>
                  Target Process PID
                </label>
                <input
                  type="text"
                  placeholder="Optional PID (leave blank for all)"
                  value={targetPid}
                  onChange={(e) => setTargetPid(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '9px 12px',
                    borderRadius: '6px',
                    border: '1px solid var(--border)',
                    background: 'var(--bg-input)',
                    color: 'var(--text)',
                    fontSize: '13px',
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: '10px', alignItems: 'flex-end', paddingTop: '18px' }}>
                <button
                  onClick={() => runMemoryScan(false)}
                  disabled={memLoading}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '9px 18px',
                    borderRadius: '6px',
                    background: '#8b5cf6',
                    color: '#fff',
                    border: 'none',
                    fontWeight: 600,
                    fontSize: '13px',
                    cursor: memLoading ? 'not-allowed' : 'pointer',
                  }}
                >
                  {memLoading ? <RefreshCw size={15} className="spin" /> : <Cpu size={15} />}
                  Scan Process Memory (VAD)
                </button>

                <button
                  onClick={() => runMemoryScan(true)}
                  disabled={memLoading}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '9px 16px',
                    borderRadius: '6px',
                    background: 'rgba(139, 92, 246, 0.15)',
                    color: '#c084fc',
                    border: '1px solid rgba(139, 92, 246, 0.3)',
                    fontWeight: 600,
                    fontSize: '13px',
                    cursor: memLoading ? 'not-allowed' : 'pointer',
                  }}
                >
                  <Bug size={15} />
                  Simulate RWX Stager (T1055 Demo)
                </button>
              </div>
            </div>

            {memError && (
              <div style={{ marginTop: '14px', padding: '10px 14px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '6px', color: '#f87171', fontSize: '13px' }}>
                Error: {memError}
              </div>
            )}
          </div>

          {/* Results Display */}
          {memReport && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
              {/* Summary Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px' }}>
                <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Processes Inspected</div>
                  <div style={{ fontSize: '22px', fontWeight: 700, marginTop: '4px' }}>{memReport.total_processes_scanned}</div>
                </div>

                <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Unbacked RWX Regions</div>
                  <div style={{ fontSize: '22px', fontWeight: 700, marginTop: '4px', color: memReport.suspicious_regions_found > 0 ? '#f59e0b' : '#10b981' }}>
                    {memReport.suspicious_regions_found}
                  </div>
                </div>

                <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Critical Injections</div>
                  <div style={{ fontSize: '22px', fontWeight: 700, marginTop: '4px', color: memReport.critical_injections_found > 0 ? '#ef4444' : '#10b981' }}>
                    {memReport.critical_injections_found}
                  </div>
                </div>

                <div style={{ background: 'var(--bg-card)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>MITRE ATT&CK Classification</div>
                  <div style={{ fontSize: '14px', fontWeight: 700, marginTop: '8px', color: '#c084fc' }}>
                    T1055: Process Injection
                  </div>
                </div>
              </div>

              {/* Injected Regions Cards */}
              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border)', overflow: 'hidden' }}>
                <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontWeight: 600, fontSize: '14px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Cpu size={16} color="#8b5cf6" />
                    Unbacked Executable Memory Regions
                  </div>
                  <span style={{ fontSize: '11px', padding: '2px 8px', borderRadius: '12px', background: 'rgba(139,92,246,0.15)', color: '#c084fc', fontWeight: 600 }}>
                    {memReport.regions.length} Regions
                  </span>
                </div>

                {memReport.regions.length === 0 ? (
                  <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
                    No unbacked executable memory pages detected. All running process memory appears legitimately backed by disk binaries.
                  </div>
                ) : (
                  <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
                    {memReport.regions.map((reg, idx) => (
                      <div
                        key={idx}
                        style={{
                          background: 'rgba(255,255,255,0.02)',
                          border: reg.severity === 'CRITICAL' ? '1px solid rgba(239,68,68,0.4)' : '1px solid var(--border)',
                          borderRadius: '8px',
                          padding: '16px',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '10px' }}>
                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                              <span style={{ fontWeight: 700, fontSize: '15px' }}>{reg.process_name}</span>
                              <span style={{ fontSize: '12px', background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: '4px', fontFamily: 'monospace' }}>
                                PID {reg.pid}
                              </span>
                              <span style={{
                                padding: '2px 8px',
                                borderRadius: '4px',
                                fontSize: '11px',
                                fontWeight: 700,
                                background: reg.severity === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : 'rgba(245,158,11,0.2)',
                                color: reg.severity === 'CRITICAL' ? '#f87171' : '#fbbf24',
                              }}>
                                {reg.severity}
                              </span>
                            </div>
                            <div style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'monospace', marginTop: '4px' }}>
                              Base Address: {reg.base_address} | Region Size: {(reg.region_size / 1024).toFixed(1)} KB | {reg.protection}
                            </div>
                          </div>

                          {/* Entropy Meter */}
                          <div style={{ textAlign: 'right' }}>
                            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '2px' }}>Shannon Entropy</div>
                            <div style={{ fontSize: '16px', fontWeight: 700, color: reg.entropy > 6.5 ? '#ef4444' : reg.entropy > 5.0 ? '#f59e0b' : '#10b981' }}>
                              {reg.entropy.toFixed(2)} / 8.00
                            </div>
                            <div style={{ width: '80px', height: '4px', background: 'rgba(255,255,255,0.1)', borderRadius: '2px', overflow: 'hidden', marginTop: '4px' }}>
                              <div style={{ width: `${(reg.entropy / 8.0) * 100}%`, height: '100%', background: reg.entropy > 6.5 ? '#ef4444' : '#10b981' }} />
                            </div>
                          </div>
                        </div>

                        {/* Indicators */}
                        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '10px' }}>
                          {reg.indicators.map((ind, ii) => (
                            <span key={ii} style={{ padding: '3px 8px', background: 'rgba(239,68,68,0.15)', color: '#f87171', borderRadius: '4px', fontSize: '11px', fontWeight: 600 }}>
                              {ind}
                            </span>
                          ))}
                        </div>

                        {/* Hex Preview Dump */}
                        {reg.hex_preview && (
                          <div style={{ background: 'rgba(0,0,0,0.3)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '4px', letterSpacing: '0.05em' }}>
                              Memory Payload Hex Preview (First 32 Bytes)
                            </div>
                            <div style={{ fontFamily: 'monospace', fontSize: '12px', letterSpacing: '0.1em', color: '#38bdf8' }}>
                              {reg.hex_preview}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
