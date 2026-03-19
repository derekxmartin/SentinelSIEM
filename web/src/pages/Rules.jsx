import { useState, useMemo } from 'react'
import { ShieldCheckIcon, ListBulletIcon, TableCellsIcon, FunnelIcon } from '@heroicons/react/24/outline'
import usePageTitle from '../hooks/usePageTitle'
import RulesList from '../components/RulesList'
import AttackHeatmap from '../components/AttackHeatmap'
import { mockRules } from '../data/mockRules'

const tabs = [
  { id: 'list', label: 'Detection Rules', icon: ListBulletIcon },
  { id: 'heatmap', label: 'ATT&CK Coverage', icon: TableCellsIcon },
]

export default function Rules() {
  usePageTitle('Rules')
  const [activeTab, setActiveTab] = useState('list')
  const [rules, setRules] = useState(mockRules)
  const [severityFilter, setSeverityFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [enabledFilter, setEnabledFilter] = useState('')

  const filteredRules = useMemo(() => {
    let result = rules
    if (severityFilter) result = result.filter((r) => r.severity === severityFilter)
    if (sourceFilter) result = result.filter((r) => r.source === sourceFilter)
    if (enabledFilter === 'enabled') result = result.filter((r) => r.enabled)
    if (enabledFilter === 'disabled') result = result.filter((r) => !r.enabled)
    return result
  }, [rules, severityFilter, sourceFilter, enabledFilter])

  const ruleStats = useMemo(() => ({
    total: rules.length,
    enabled: rules.filter((r) => r.enabled).length,
    totalHits: rules.reduce((sum, r) => sum + r.hitCount, 0),
  }), [rules])

  function handleToggle(ruleId) {
    setRules((prev) => prev.map((r) => r.id === ruleId ? { ...r, enabled: !r.enabled } : r))
  }

  const hasFilters = severityFilter || sourceFilter || enabledFilter

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheckIcon className="h-7 w-7 text-indigo-400" />
          <h1 className="text-2xl font-semibold">Rules</h1>
          <span className="text-sm text-slate-500 dark:text-slate-400">
            {ruleStats.enabled}/{ruleStats.total} enabled
          </span>
        </div>
      </div>

      {/* KPI row */}
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Total Rules</p>
          <p className="text-2xl font-bold mt-1 text-slate-900 dark:text-white">{ruleStats.total}</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Enabled</p>
          <p className="text-2xl font-bold mt-1 text-slate-900 dark:text-white">{ruleStats.enabled}</p>
          <div className="mt-2 h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
            <div
              className="h-full rounded-full bg-green-500"
              style={{ width: `${(ruleStats.enabled / ruleStats.total) * 100}%` }}
            />
          </div>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Total Hits</p>
          <p className="text-2xl font-bold mt-1 text-slate-900 dark:text-white">{ruleStats.totalHits.toLocaleString()}</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-700">
        <div className="flex gap-1">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px ${
                activeTab === tab.id
                  ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Filters (list view only) */}
        {activeTab === 'list' && (
          <div className="flex items-center gap-2 pb-2">
            <FunnelIcon className="h-4 w-4 text-slate-400" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-2 py-1 rounded-lg text-xs border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="px-2 py-1 rounded-lg text-xs border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300"
            >
              <option value="">All Sources</option>
              <option value="sigma_curated">Sigma</option>
              <option value="akeso_portfolio">Akeso</option>
            </select>
            <select
              value={enabledFilter}
              onChange={(e) => setEnabledFilter(e.target.value)}
              className="px-2 py-1 rounded-lg text-xs border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300"
            >
              <option value="">All States</option>
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
            {hasFilters && (
              <button
                onClick={() => { setSeverityFilter(''); setSourceFilter(''); setEnabledFilter('') }}
                className="text-xs text-indigo-400 hover:text-indigo-300"
              >
                Clear
              </button>
            )}
          </div>
        )}
      </div>

      {/* Tab content */}
      {activeTab === 'list' && (
        <RulesList rules={filteredRules} onToggle={handleToggle} />
      )}
      {activeTab === 'heatmap' && (
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <AttackHeatmap />
        </div>
      )}
    </div>
  )
}
