import { useState, useMemo, Fragment } from 'react'
import { ChevronRightIcon } from '@heroicons/react/24/outline'
import SeverityBadge from './SeverityBadge'
import { mitreTactics } from '../data/mockRules'

const sourceLabel = {
  sigma_curated: 'Sigma',
  sentinel_portfolio: 'Sentinel',
}

const sourceBadgeClass = {
  sigma_curated: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
  sentinel_portfolio: 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300',
}

function formatTriggered(ts) {
  if (!ts) return 'Never'
  const diff = Date.now() - new Date(ts).getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

export default function RulesList({ rules, onToggle }) {
  const [collapsed, setCollapsed] = useState({})
  const [expandedRule, setExpandedRule] = useState(null)

  const grouped = useMemo(() => {
    const map = {}
    for (const tactic of mitreTactics) {
      const tacticRules = rules.filter((r) => r.tactic === tactic)
      if (tacticRules.length > 0) map[tactic] = tacticRules
    }
    return map
  }, [rules])

  function toggleCollapse(tactic) {
    setCollapsed((prev) => ({ ...prev, [tactic]: !prev[tactic] }))
  }

  return (
    <div className="space-y-2">
      {Object.entries(grouped).map(([tactic, tacticRules]) => (
        <div key={tactic} className="rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
          {/* Tactic header */}
          <button
            onClick={() => toggleCollapse(tactic)}
            className="w-full flex items-center justify-between px-4 py-2.5 bg-slate-50 dark:bg-slate-800/50 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <div className="flex items-center gap-2">
              <ChevronRightIcon
                className={`h-4 w-4 text-slate-400 transition-transform ${collapsed[tactic] ? '' : 'rotate-90'}`}
              />
              <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">{tactic}</span>
              <span className="text-xs text-slate-400">({tacticRules.length} rule{tacticRules.length !== 1 ? 's' : ''})</span>
            </div>
            <div className="flex items-center gap-3 text-xs text-slate-400">
              <span>{tacticRules.filter((r) => r.enabled).length} enabled</span>
              <span>{tacticRules.reduce((sum, r) => sum + r.hitCount, 0).toLocaleString()} hits</span>
            </div>
          </button>

          {/* Rules list */}
          {!collapsed[tactic] && (
            <div className="divide-y divide-slate-100 dark:divide-slate-800">
              {tacticRules.map((rule) => (
                <Fragment key={rule.id}>
                  <div
                    onClick={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)}
                    className={`flex items-center gap-3 px-4 py-2.5 cursor-pointer transition-colors ${
                      expandedRule === rule.id
                        ? 'bg-indigo-50 dark:bg-indigo-500/10'
                        : 'bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                    }`}
                  >
                    {/* Toggle */}
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        onToggle(rule.id)
                      }}
                      className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors flex-shrink-0 ${
                        rule.enabled ? 'bg-indigo-600' : 'bg-slate-300 dark:bg-slate-600'
                      }`}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 rounded-full bg-white shadow-sm transition-transform ${
                          rule.enabled ? 'translate-x-[1.125rem]' : 'translate-x-[0.1875rem]'
                        }`}
                      />
                    </button>

                    {/* Severity */}
                    <div className="w-20 flex-shrink-0">
                      <SeverityBadge severity={rule.severity} />
                    </div>

                    {/* Name */}
                    <div className="flex-1 min-w-0">
                      <span className={`text-sm font-medium truncate block ${
                        rule.enabled ? 'text-slate-800 dark:text-slate-200' : 'text-slate-400 dark:text-slate-500'
                      }`}>
                        {rule.name}
                      </span>
                    </div>

                    {/* Technique */}
                    <span className="hidden md:inline text-xs font-mono text-slate-400 w-20 flex-shrink-0">
                      {rule.techniqueId}
                    </span>

                    {/* Source badge */}
                    <span className={`hidden lg:inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium ${sourceBadgeClass[rule.source]}`}>
                      {sourceLabel[rule.source]}
                    </span>

                    {/* Hit count */}
                    <div className="w-16 text-right flex-shrink-0">
                      <span className="text-sm font-mono text-slate-600 dark:text-slate-300">
                        {rule.hitCount.toLocaleString()}
                      </span>
                    </div>

                    {/* Last triggered */}
                    <div className="w-16 text-right flex-shrink-0 hidden sm:block">
                      <span className="text-xs text-slate-400">{formatTriggered(rule.lastTriggered)}</span>
                    </div>
                  </div>

                  {/* Expanded detail row */}
                  {expandedRule === rule.id && (
                    <div className="px-4 py-3 bg-slate-50 dark:bg-slate-800/30 border-t border-slate-100 dark:border-slate-800">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                        <div>
                          <p className="text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider mb-1">Description</p>
                          <p className="text-slate-700 dark:text-slate-300">{rule.description}</p>
                        </div>
                        <div className="space-y-2">
                          <div className="flex gap-4">
                            <div>
                              <p className="text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider">Technique</p>
                              <p className="text-slate-700 dark:text-slate-300 font-mono text-xs">{rule.techniqueId} — {rule.techniqueName}</p>
                            </div>
                          </div>
                          <div className="flex gap-4">
                            <div>
                              <p className="text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider">Author</p>
                              <p className="text-slate-700 dark:text-slate-300">{rule.author}</p>
                            </div>
                            <div>
                              <p className="text-slate-500 dark:text-slate-400 text-xs uppercase tracking-wider">Last Triggered</p>
                              <p className="text-slate-700 dark:text-slate-300">{rule.lastTriggered ? new Date(rule.lastTriggered).toLocaleString() : 'Never'}</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </Fragment>
              ))}
            </div>
          )}
        </div>
      ))}

      {Object.keys(grouped).length === 0 && (
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-8 text-center text-slate-400">
          No rules match the current filters.
        </div>
      )}
    </div>
  )
}
