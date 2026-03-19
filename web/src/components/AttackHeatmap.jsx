import { useState, useMemo } from 'react'
import { ArrowDownTrayIcon, ArrowsPointingOutIcon, ArrowsPointingInIcon } from '@heroicons/react/24/outline'
import { mitreTactics, attackCoverage, computeCoverageStats, generateNavigatorJSON } from '../data/mockRules'

const coverageColors = {
  full: 'bg-green-500/80 hover:bg-green-500 border-green-600/30',
  partial: 'bg-amber-500/80 hover:bg-amber-500 border-amber-600/30',
  none: 'bg-slate-200 hover:bg-slate-300 dark:bg-slate-700 dark:hover:bg-slate-600 border-slate-300/30 dark:border-slate-600/30',
}

const coverageLabels = {
  full: 'Full Coverage',
  partial: 'Partial Coverage',
  none: 'No Coverage',
}

function CoverageCell({ technique, compact }) {
  const [showTooltip, setShowTooltip] = useState(false)

  return (
    <div className="relative">
      <div
        onMouseEnter={() => setShowTooltip(true)}
        onMouseLeave={() => setShowTooltip(false)}
        className={`rounded border cursor-default transition-colors ${coverageColors[technique.coverage]} ${
          compact ? 'h-6' : 'px-2 py-1.5'
        }`}
      >
        {!compact && (
          <span className={`text-xs leading-tight block truncate ${
            technique.coverage === 'none'
              ? 'text-slate-500 dark:text-slate-400'
              : 'text-white font-medium'
          }`}>
            {technique.id}
          </span>
        )}
      </div>

      {/* Tooltip */}
      {showTooltip && (
        <div className="absolute z-50 bottom-full left-1/2 -translate-x-1/2 mb-2 w-56 pointer-events-none">
          <div className="bg-slate-800 dark:bg-slate-700 text-white text-xs rounded-lg p-2.5 shadow-xl">
            <p className="font-semibold">{technique.id}</p>
            <p className="text-slate-300 mt-0.5">{technique.name}</p>
            <p className={`mt-1 font-medium ${
              technique.coverage === 'full' ? 'text-green-400' : technique.coverage === 'partial' ? 'text-amber-400' : 'text-red-400'
            }`}>
              {coverageLabels[technique.coverage]}
            </p>
            <div className="absolute left-1/2 -translate-x-1/2 top-full w-2 h-2 bg-slate-800 dark:bg-slate-700 rotate-45 -mt-1" />
          </div>
        </div>
      )}
    </div>
  )
}

export default function AttackHeatmap() {
  const [compact, setCompact] = useState(false)
  const stats = useMemo(() => computeCoverageStats(attackCoverage), [])

  const overallStats = useMemo(() => {
    let totalTech = 0, fullTech = 0, partialTech = 0
    for (const s of Object.values(stats)) {
      totalTech += s.total
      fullTech += s.full
      partialTech += s.partial
    }
    const pct = totalTech > 0 ? Math.round(((fullTech + partialTech * 0.5) / totalTech) * 100) : 0
    return { totalTech, fullTech, partialTech, noneTech: totalTech - fullTech - partialTech, pct }
  }, [stats])

  function handleExport() {
    const json = generateNavigatorJSON(attackCoverage)
    const blob = new Blob([JSON.stringify(json, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'akeso-attack-navigator.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-4">
          <div className="text-center">
            <p className="text-2xl font-bold text-slate-900 dark:text-white">{overallStats.pct}%</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">Overall Coverage</p>
          </div>
          <div className="h-8 w-px bg-slate-200 dark:bg-slate-700" />
          <div className="flex items-center gap-4 text-xs">
            <span className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-green-500" />
              Full ({overallStats.fullTech})
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-amber-500" />
              Partial ({overallStats.partialTech})
            </span>
            <span className="flex items-center gap-1.5">
              <span className="h-3 w-3 rounded bg-slate-300 dark:bg-slate-600" />
              None ({overallStats.noneTech})
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setCompact(!compact)}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
          >
            {compact ? <ArrowsPointingOutIcon className="h-3.5 w-3.5" /> : <ArrowsPointingInIcon className="h-3.5 w-3.5" />}
            {compact ? 'Expand' : 'Compact'}
          </button>
          <button
            onClick={handleExport}
            className="flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
          >
            <ArrowDownTrayIcon className="h-3.5 w-3.5" />
            Navigator JSON
          </button>
        </div>
      </div>

      {/* Heatmap grid */}
      <div className="overflow-x-auto">
        <div className="grid gap-2" style={{ gridTemplateColumns: `repeat(${mitreTactics.length}, minmax(0, 1fr))`, minWidth: compact ? '700px' : '1100px' }}>
          {/* Tactic headers */}
          {mitreTactics.map((tactic) => (
            <div key={tactic} className="text-center">
              <p className={`font-semibold text-slate-700 dark:text-slate-200 ${compact ? 'text-[9px]' : 'text-[10px]'} leading-tight`}>
                {tactic}
              </p>
              <p className={`text-slate-400 mt-0.5 ${compact ? 'text-[8px]' : 'text-[9px]'}`}>
                {stats[tactic]?.pct ?? 0}%
              </p>
            </div>
          ))}

          {/* Technique cells */}
          {mitreTactics.map((tactic) => (
            <div key={tactic} className="space-y-1">
              {(attackCoverage[tactic] || []).map((tech) => (
                <CoverageCell key={tech.id} technique={tech} compact={compact} />
              ))}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
