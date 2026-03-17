import { useNavigate } from 'react-router-dom'
import {
  ShieldExclamationIcon,
  FolderIcon,
  DocumentTextIcon,
  SignalIcon,
  ServerStackIcon,
} from '@heroicons/react/24/outline'

const severityColors = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-blue-500/20 text-blue-400',
}

const quadrantColors = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
}

function SeverityBadge({ severity }) {
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${severityColors[severity] || severityColors.low}`}>
      {severity}
    </span>
  )
}

export default function EntityResults({ results, query, onClose }) {
  const navigate = useNavigate()

  if (!results) return null

  const { host_scores, alerts, cases, events, rules } = results
  const hasResults = (host_scores?.length > 0) || alerts?.total > 0 || cases?.total > 0 || events?.total > 0 || rules?.length > 0

  if (!hasResults) {
    return (
      <div className="p-6 text-center text-sm text-slate-500">
        No results found for "{query}"
      </div>
    )
  }

  return (
    <div className="divide-y divide-slate-700/50">
      {/* NDR Host Scores */}
      {host_scores?.length > 0 && (
        <ResultGroup title="Host Scores" icon={SignalIcon} count={host_scores.length}>
          {host_scores.map((hs, i) => (
            <button
              key={i}
              onClick={() => { onClose(); navigate(`/hunt?q=source.ip:${hs.host_ip}`) }}
              className="flex items-center gap-3 w-full px-3 py-2 text-left text-sm text-slate-300 hover:bg-slate-700/50 rounded"
            >
              <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${quadrantColors[hs.quadrant] || quadrantColors.low}`}>
                {hs.quadrant}
              </span>
              <span className="font-mono">{hs.host_ip}</span>
              {hs.host_name && <span className="text-slate-500">{hs.host_name}</span>}
              <span className="ml-auto text-xs text-slate-500">
                T:{hs.threat} C:{hs.certainty}
              </span>
            </button>
          ))}
        </ResultGroup>
      )}

      {/* Alerts */}
      {alerts?.total > 0 && (
        <ResultGroup title="Alerts" icon={ShieldExclamationIcon} count={alerts.total}>
          {alerts.items.map((a) => (
            <button
              key={a.id}
              onClick={() => { onClose(); navigate(`/alerts?highlight=${a.id}`) }}
              className="flex items-center gap-3 w-full px-3 py-2 text-left text-sm text-slate-300 hover:bg-slate-700/50 rounded"
            >
              <SeverityBadge severity={a.severity} />
              <span className="truncate flex-1">{a.rule_name}</span>
              <span className="text-xs text-slate-500 shrink-0">
                {formatTimestamp(a.timestamp)}
              </span>
            </button>
          ))}
          {alerts.total > alerts.items.length && (
            <ViewAll label={`View all ${alerts.total} alerts`} onClick={() => { onClose(); navigate(`/alerts?q=${encodeURIComponent(query)}`) }} />
          )}
        </ResultGroup>
      )}

      {/* Cases */}
      {cases?.total > 0 && (
        <ResultGroup title="Cases" icon={FolderIcon} count={cases.total}>
          {cases.items.map((c) => (
            <button
              key={c.id}
              onClick={() => { onClose(); navigate(`/cases?highlight=${c.id}`) }}
              className="flex items-center gap-3 w-full px-3 py-2 text-left text-sm text-slate-300 hover:bg-slate-700/50 rounded"
            >
              <SeverityBadge severity={c.severity} />
              <span className="truncate flex-1">{c.title}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700 text-slate-400">{c.status}</span>
            </button>
          ))}
        </ResultGroup>
      )}

      {/* Events */}
      {events?.total > 0 && (
        <ResultGroup title="Events" icon={ServerStackIcon} count={events.total}>
          <button
            onClick={() => { onClose(); navigate(`/hunt?q=${encodeURIComponent(query)}`) }}
            className="flex items-center gap-2 w-full px-3 py-2 text-left text-sm text-slate-300 hover:bg-slate-700/50 rounded"
          >
            <span>{events.total.toLocaleString()} events</span>
            <div className="flex gap-1 ml-auto">
              {Object.entries(events.by_source || {}).map(([src, count]) => (
                <span key={src} className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300">
                  {src}: {count}
                </span>
              ))}
            </div>
          </button>
        </ResultGroup>
      )}

      {/* Rules */}
      {rules?.length > 0 && (
        <ResultGroup title="Rules" icon={DocumentTextIcon} count={rules.length}>
          {rules.slice(0, 5).map((r) => (
            <button
              key={r.id}
              onClick={() => { onClose(); navigate(`/rules?highlight=${r.id}`) }}
              className="flex items-center gap-3 w-full px-3 py-2 text-left text-sm text-slate-300 hover:bg-slate-700/50 rounded"
            >
              <SeverityBadge severity={r.severity} />
              <span className="truncate flex-1">{r.name}</span>
            </button>
          ))}
        </ResultGroup>
      )}
    </div>
  )
}

function ResultGroup({ title, icon: Icon, count, children }) {
  return (
    <div className="py-1">
      <div className="flex items-center gap-2 px-3 py-1.5">
        <Icon className="h-3.5 w-3.5 text-slate-500" />
        <span className="text-xs font-medium text-slate-400 uppercase">{title}</span>
        <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-slate-700 text-slate-400">{count}</span>
      </div>
      {children}
    </div>
  )
}

function ViewAll({ label, onClick }) {
  return (
    <button
      onClick={onClick}
      className="w-full px-3 py-1.5 text-left text-xs text-indigo-400 hover:text-indigo-300"
    >
      {label} →
    </button>
  )
}

function formatTimestamp(ts) {
  if (!ts) return ''
  try {
    const d = new Date(ts)
    const now = new Date()
    const diffMs = now - d
    if (diffMs < 3600000) return `${Math.floor(diffMs / 60000)}m ago`
    if (diffMs < 86400000) return `${Math.floor(diffMs / 3600000)}h ago`
    return d.toLocaleDateString()
  } catch {
    return ts
  }
}
