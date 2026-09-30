import React, { useState, useEffect } from 'react'
import {
  Blocks,
  ShieldCheck,
  Search,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Hash,
  Clock,
  User,
  FileCheck,
  Lock,
  ArrowRight,
  ExternalLink,
} from 'lucide-react'

interface EvidenceRecord {
  id: string
  record_type: string
  target: string
  sha256_hash: string
  operator: string
  timestamp: string
  metadata_json: string
}

interface LedgerBlock {
  index: number
  timestamp: string
  previous_hash: string
  merkle_root: string
  records: EvidenceRecord[]
  leaf_hashes: string[]
  nonce: number
  block_hash: string
  signature: string
}

interface LedgerResponse {
  status: string
  total_blocks: number
  chain_valid: boolean
  network: string
  blocks: LedgerBlock[]
}

export function BlockchainLedger() {
  const [ledger, setLedger] = useState<LedgerResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [verifyResult, setVerifyResult] = useState<any | null>(null)
  const [verifying, setVerifying] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchLedger = async () => {
    try {
      setLoading(true)
      const res = await fetch('/api/blockchain/ledger')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data: LedgerResponse = await res.json()
      setLedger(data)
      setError(null)
    } catch (err: any) {
      setError(err.message || 'Failed to load ledger')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchLedger()
    const interval = setInterval(fetchLedger, 5000)
    return () => clearInterval(interval)
  }, [])

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!searchQuery.trim()) return
    try {
      setVerifying(true)
      const res = await fetch('/api/blockchain/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: jsonString({ query: searchQuery.trim() }),
      })
      const data = await res.json()
      setVerifyResult(data)
    } catch (err: any) {
      setVerifyResult({ verified: false, detail: err.message })
    } finally {
      setVerifying(false)
    }
  }

  function jsonString(obj: any) {
    return JSON.stringify(obj)
  }

  return (
    <div className="panel" style={{ padding: '24px', maxWidth: '1400px', margin: '0 auto' }}>
      {/* ── Header ────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '36px', height: '36px', borderRadius: '8px',
              background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 15px rgba(16, 185, 129, 0.4)'
            }}>
              <Blocks size={20} color="#fff" />
            </div>
            <div>
              <h1 style={{ fontSize: '20px', fontWeight: 700, margin: 0 }}>
                CARVE Immutable Audit Ledger
              </h1>
              <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)' }}>
                Cryptographic Chain-of-Custody & Merkle-Root Verification (SIH 2026 Theme: Blockchain & Cybersecurity)
              </p>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px' }}>
          <button
            onClick={fetchLedger}
            className="btn btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '13px' }}
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {/* ── Status Metrics ─────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px', marginBottom: '24px' }}>
        <div style={{ background: 'var(--bg-secondary)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>CHAIN STATUS</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={20} color={ledger?.chain_valid ? '#10b981' : '#ef4444'} />
            <span style={{ fontSize: '18px', fontWeight: 700, color: ledger?.chain_valid ? '#10b981' : '#ef4444' }}>
              {ledger?.chain_valid ? 'CRYPTOGRAPHICALLY VALID' : 'TAMPER DETECTED'}
            </span>
          </div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>TOTAL BLOCKS MINTED</div>
          <div style={{ fontSize: '22px', fontWeight: 700, color: 'var(--text-primary)' }}>
            {ledger?.total_blocks ?? 0} Blocks
          </div>
        </div>

        <div style={{ background: 'var(--bg-secondary)', padding: '16px', borderRadius: '10px', border: '1px solid var(--border-color)' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '4px' }}>ACTIVE NETWORK</div>
          <div style={{ fontSize: '14px', fontWeight: 600, color: '#38bdf8', fontFamily: 'monospace' }}>
            {ledger?.network || 'CARVE-PRIVATE-AUDIT-LEDGER'}
          </div>
        </div>
      </div>

      {/* ── Search & Verify Widget ─────────────────────────────── */}
      <div style={{
        background: 'var(--bg-secondary)',
        padding: '20px',
        borderRadius: '12px',
        border: '1px solid var(--border-color)',
        marginBottom: '28px',
      }}>
        <h3 style={{ fontSize: '15px', fontWeight: 600, margin: '0 0 12px 0', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Search size={16} color="#38bdf8" /> Proof-of-Integrity Verification
        </h3>
        <form onSubmit={handleVerify} style={{ display: 'flex', gap: '10px' }}>
          <input
            type="text"
            placeholder="Paste Certificate ID (e.g. JKY-CERT-...) or SHA-256 evidence hash to verify..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              flex: 1,
              padding: '10px 14px',
              borderRadius: '8px',
              background: 'var(--bg-primary)',
              border: '1px solid var(--border-color)',
              color: 'var(--text-primary)',
              fontSize: '13px',
              fontFamily: 'monospace'
            }}
          />
          <button
            type="submit"
            className="btn btn-primary"
            disabled={verifying}
            style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '0 20px' }}
          >
            {verifying ? <RefreshCw size={14} className="spin" /> : <ShieldCheck size={16} />}
            Verify On Chain
          </button>
        </form>

        {verifyResult && (
          <div style={{
            marginTop: '16px',
            padding: '16px',
            borderRadius: '8px',
            background: verifyResult.verified ? 'rgba(16, 185, 129, 0.1)' : 'rgba(239, 68, 68, 0.1)',
            border: `1px solid ${verifyResult.verified ? '#10b981' : '#ef4444'}`,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              {verifyResult.verified ? (
                <>
                  <CheckCircle2 size={18} color="#10b981" />
                  <span style={{ fontWeight: 700, color: '#10b981', fontSize: '14px' }}>
                    CHAIN VERIFIED: Evidence anchored on Block #{verifyResult.block_index}
                  </span>
                </>
              ) : (
                <>
                  <AlertTriangle size={18} color="#ef4444" />
                  <span style={{ fontWeight: 700, color: '#ef4444', fontSize: '14px' }}>
                    VERIFICATION FAILED: {verifyResult.detail || 'Target not found on ledger'}
                  </span>
                </>
              )}
            </div>

            {verifyResult.verified && verifyResult.record && (
              <div style={{ fontSize: '12px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '8px', marginTop: '10px' }}>
                <div><strong>Record ID:</strong> <span style={{ fontFamily: 'monospace' }}>{verifyResult.record.id}</span></div>
                <div><strong>Type:</strong> <span className="badge">{verifyResult.record.record_type}</span></div>
                <div><strong>Target:</strong> {verifyResult.record.target}</div>
                <div><strong>Anchored:</strong> {verifyResult.block_timestamp}</div>
                <div style={{ gridColumn: '1 / -1', wordBreak: 'break-all' }}>
                  <strong>Merkle Root:</strong> <span style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{verifyResult.merkle_root}</span>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Block Explorer ─────────────────────────────────────── */}
      <h3 style={{ fontSize: '16px', fontWeight: 600, marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
        <Hash size={18} color="#10b981" /> Immutable Chain Blocks (Most Recent First)
      </h3>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {ledger?.blocks.slice().reverse().map((block) => (
          <div
            key={block.index}
            style={{
              background: 'var(--bg-secondary)',
              borderRadius: '10px',
              border: '1px solid var(--border-color)',
              padding: '18px',
              transition: 'border-color 0.2s',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-color)', paddingBottom: '12px', marginBottom: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{
                  padding: '4px 10px',
                  borderRadius: '6px',
                  background: block.index === 0 ? 'rgba(56, 189, 248, 0.2)' : 'rgba(16, 185, 129, 0.2)',
                  color: block.index === 0 ? '#38bdf8' : '#10b981',
                  fontWeight: 700,
                  fontSize: '13px',
                }}>
                  {block.index === 0 ? 'GENESIS BLOCK #0' : `BLOCK #${block.index}`}
                </span>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                  <Clock size={13} /> {block.timestamp}
                </span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                Nonce: <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>{block.nonce}</span>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '12px', fontSize: '12px', marginBottom: '16px' }}>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Block Hash:</span>
                <div style={{ fontFamily: 'monospace', color: '#10b981', wordBreak: 'break-all' }}>{block.block_hash}</div>
              </div>
              <div>
                <span style={{ color: 'var(--text-muted)' }}>Previous Block Hash:</span>
                <div style={{ fontFamily: 'monospace', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>{block.previous_hash}</div>
              </div>
              <div style={{ gridColumn: '1 / -1' }}>
                <span style={{ color: 'var(--text-muted)' }}>Merkle Root (Leaf Count: {block.records.length}):</span>
                <div style={{ fontFamily: 'monospace', color: '#38bdf8', wordBreak: 'break-all' }}>{block.merkle_root}</div>
              </div>
            </div>

            {/* Embedded Records */}
            <div>
              <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '8px' }}>
                Anchored Evidence Records ({block.records.length})
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {block.records.map((rec, rIdx) => (
                  <div
                    key={rIdx}
                    style={{
                      background: 'var(--bg-primary)',
                      padding: '10px 14px',
                      borderRadius: '6px',
                      border: '1px solid var(--border-color)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      fontSize: '12px'
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{rec.id}</span>
                        <span style={{
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: '10px',
                          fontWeight: 600,
                          background: rec.record_type === 'SanitizationCertificate' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(56, 189, 248, 0.2)',
                          color: rec.record_type === 'SanitizationCertificate' ? '#ef4444' : '#38bdf8',
                        }}>
                          {rec.record_type}
                        </span>
                        <span style={{ color: 'var(--text-muted)' }}>Target: {rec.target}</span>
                      </div>
                      <div style={{ fontFamily: 'monospace', color: 'var(--text-muted)', fontSize: '11px', marginTop: '4px', wordBreak: 'break-all' }}>
                        SHA-256: {rec.sha256_hash}
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--text-secondary)', fontSize: '11px' }}>
                      <User size={12} /> {rec.operator}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
