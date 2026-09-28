import { useState, useEffect, useCallback } from 'react'
import { useParams, useNavigate, useLocation } from 'react-router-dom'
import { useTheme } from '../context/ThemeContext'
import { useApiClient } from '../hooks/useApiClient'
import { ArrowLeft, RefreshCw, RotateCcw, Code2, Link2 } from 'lucide-react'

const sevStyle = (s) => ({
  critical: { bg: '#fee2e2', color: '#dc2626' },
  high: { bg: '#ffedd5', color: '#ea580c' },
  medium: { bg: '#fef9c3', color: '#a16207' },
  low: { bg: '#dcfce7', color: '#16a34a' },
  info: { bg: '#dbeafe', color: '#1d4ed8' },
}[String(s || '').toLowerCase()] || { bg: '#f3f4f6', color: '#6b7280' })

export default function VulnDetail() {
  const { vulnId } = useParams()
  const { state } = useLocation()
  const { theme } = useTheme()
  const api = useApiClient()
  const navigate = useNavigate()
  const [vuln, setVuln] = useState(null)
  const [httpResponse, setHttpResponse] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [tab, setTab] = useState('details')
  const [status, setStatus] = useState('')

  const load = useCallback(async () => {
    setLoading(true); setError(null)
    try {
      const vRes = await api.vulns.getOne(vulnId)
      const vulnData = vRes.data
      setVuln(vulnData)
      setStatus(vulnData?.status || 'open')
      
      try {
        // First try the passed state context which avoids a secondary API call and uses the correct scan payload!
        if (state?.scanId && state?.resultId) {
          const contextRes = await api.raw.get(`/scans/${state.scanId}/results/${state.resultId}/vulnerabilities/${vulnId}/http_response`)
          setHttpResponse(contextRes.data)
          return
        }
      } catch (err) {
        // If it throws 404 here, it's just Acunetix having no HTTP data for this specific vuln.
        // We catch it and let it fall through to null.
      }

      try {
        // Try direct fetch next
        const hRes = await api.vulns.getHttpResponse(vulnId)
        setHttpResponse(hRes.data)
      } catch {
        // Fallback: fetch via the Target's latest scan context if state wasn't given.
        try {
          if (vulnData.target_id) {
            const tRes = await api.targets.getOne(vulnData.target_id)
            const fallbackScanId = tRes.data.last_scan_id
            const fallbackResultId = tRes.data.last_scan_session_id

            if (fallbackScanId && fallbackResultId) {
              const hRes2 = await api.raw.get(`/scans/${fallbackScanId}/results/${fallbackResultId}/vulnerabilities/${vulnId}/http_response`)
              setHttpResponse(hRes2.data)
            } else {
              setHttpResponse(null)
            }
          } else {
            setHttpResponse(null)
          }
        } catch {
          setHttpResponse(null) // Completely unavailable (either legit 404 or missing target)
        }
      }
    } catch (e) { setError(e.response?.data?.message || e.message) }
    finally { setLoading(false) }
  }, [vulnId, api, state])

  useEffect(() => { load() }, [load])

  const updateStatus = async (s) => {
    try { await api.vulns.updateStatus(vulnId, { status: s }); setStatus(s) }
    catch (e) { alert(e.message) }
  }

  const recheck = async () => {
    try { await api.vulns.recheck(vulnId); alert('Recheck queued') }
    catch (e) { alert(e.message) }
  }

  const createIssue = async () => {
    try {
      await api.vulns.getIssues({ vuln_id_list: [vulnId] })
      alert('Issue created in configured issue tracker')
    } catch (e) { alert(e.response?.data?.message || e.message) }
  }

  const tabs = [
    { key: 'details', label: 'Details' },
    { key: 'http', label: 'HTTP Request/Response' },
    { key: 'description', label: 'Description' },
  ]

  if (loading) return <div className="text-center py-20 text-sm" style={{ color: theme.textMuted }}>Loading...</div>
  if (error) return <div className="px-4 py-3 rounded-xl text-sm" style={{ background: '#fee2e2', color: '#dc2626' }}>{error}</div>

  const ss = sevStyle(vuln?.severity)

  return (
    <div className="space-y-5 max-w-4xl">
      <div className="flex items-center gap-3">
        <button onClick={() => navigate(-1)} className="p-2 rounded-xl" style={{ background: theme.card, border: `1px solid ${theme.border}`, color: theme.textMuted }}><ArrowLeft size={16} /></button>
        <div className="flex-1">
          <h1 className="text-xl font-bold" style={{ color: theme.text }}>{vuln?.vt_name || vuln?.name || 'Vulnerability'}</h1>
          <div className="flex items-center gap-2 mt-1">
            <span className="px-2 py-0.5 rounded-lg text-xs font-semibold capitalize" style={{ background: ss.bg, color: ss.color }}>{vuln?.severity}</span>
            <span className="text-xs" style={{ color: theme.textMuted }}>{vuln?.affects_url || ''}</span>
          </div>
        </div>
        <button onClick={recheck} className="flex items-center gap-2 px-3 py-2 rounded-xl text-sm font-medium" style={{ background: theme.card, border: `1px solid ${theme.border}`, color: theme.text }}>
          <RotateCcw size={14} /> Recheck
        </button>
        <button onClick={createIssue} className="flex items-center gap-2 px-3 py-2 rounded-xl text-sm font-medium" style={{ background: theme.card, border: `1px solid ${theme.border}`, color: theme.text }}>
          <Link2 size={14} /> Create Issue
        </button>
        <select value={status} onChange={e => updateStatus(e.target.value)} className="px-3 py-2 rounded-xl text-sm outline-none font-medium" style={{ background: theme.primary, color: '#fff', border: 'none' }}>
          <option value="open">Open</option>
          <option value="fixed">Fixed</option>
          <option value="ignored">Ignored</option>
          <option value="false positive">False Positive</option>
        </select>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-xl" style={{ background: theme.card, border: `1px solid ${theme.border}` }}>
        {tabs.map(t => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className="px-4 py-2 rounded-lg text-sm font-medium transition"
            style={{ background: tab === t.key ? theme.primary : 'transparent', color: tab === t.key ? '#fff' : theme.textMuted }}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'details' && vuln && (
        <div className="rounded-2xl p-5 space-y-3" style={{ background: theme.card, border: `1px solid ${theme.border}` }}>
          {[
            ['Vulnerability Name', vuln.vt_name || vuln.name],
            ['Severity', vuln.severity],
            ['CVSS Score', vuln.cvss_score || '-'],
            ['Affects URL', vuln.affects_url || '-'],
            ['Target', vuln.target_vuln?.address || '-'],
            ['Status', vuln.status || '-'],
            ['Request', vuln.request ? vuln.request.slice(0, 200) + '...' : '-'],
          ].map(([k, v]) => (
            <div key={k} className="flex gap-4" style={{ borderBottom: `1px solid ${theme.border}`, paddingBottom: 8 }}>
              <span className="text-xs font-semibold w-36 shrink-0" style={{ color: theme.textMuted }}>{k}</span>
              <span className="text-sm font-mono break-all" style={{ color: theme.text }}>{v || '-'}</span>
            </div>
          ))}
        </div>
      )}

      {tab === 'http' && (
        <div className="space-y-4">
          {httpResponse ? (
            <>
              <div className="rounded-2xl p-4" style={{ background: theme.card, border: `1px solid ${theme.border}` }}>
                <div className="flex items-center gap-2 mb-2">
                  <Code2 size={14} style={{ color: theme.primary }} />
                  <span className="text-sm font-semibold" style={{ color: theme.text }}>Request</span>
                </div>
                <pre className="text-xs overflow-x-auto p-3 rounded-lg" style={{ background: theme.bg, color: theme.textMuted, maxHeight: 300 }}>{httpResponse.request || 'N/A'}</pre>
              </div>
              <div className="rounded-2xl p-4" style={{ background: theme.card, border: `1px solid ${theme.border}` }}>
                <div className="flex items-center gap-2 mb-2">
                  <Code2 size={14} style={{ color: theme.primary }} />
                  <span className="text-sm font-semibold" style={{ color: theme.text }}>Response</span>
                </div>
                <pre className="text-xs overflow-x-auto p-3 rounded-lg" style={{ background: theme.bg, color: theme.textMuted, maxHeight: 300 }}>{httpResponse.response || 'N/A'}</pre>
              </div>
            </>
          ) : <div className="text-center py-10 text-sm" style={{ color: theme.textMuted }}>No HTTP data available</div>}
        </div>
      )}

      {tab === 'description' && (
        <div className="rounded-2xl p-5" style={{ background: theme.card, border: `1px solid ${theme.border}` }}>
          <div className="prose max-w-none text-sm" style={{ color: theme.text }}
            dangerouslySetInnerHTML={{ __html: vuln?.description || vuln?.recommendation || 'No description available' }}
          />
          {vuln?.recommendation && (
            <div className="mt-4 pt-4" style={{ borderTop: `1px solid ${theme.border}` }}>
              <h4 className="font-semibold text-sm mb-2" style={{ color: theme.text }}>Recommendation</h4>
              <div className="text-sm" style={{ color: theme.textMuted }}
                dangerouslySetInnerHTML={{ __html: vuln.recommendation }}
              />
            </div>
          )}
        </div>
      )}
    </div>
  )
}
