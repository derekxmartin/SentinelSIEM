import { useState, useMemo } from 'react'
import { BellAlertIcon, FunnelIcon } from '@heroicons/react/24/outline'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  flexRender,
} from '@tanstack/react-table'
import SeverityBadge, { getSeverityBorderClass } from '../components/SeverityBadge'
import StatusBadge from '../components/StatusBadge'
import AlertFlyout from '../components/AlertFlyout'
import { mockAlerts } from '../data/mockAlerts'

function formatTimestamp(ts) {
  const d = new Date(ts)
  const diff = Date.now() - d.getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return d.toLocaleDateString()
}

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }

const columns = [
  {
    id: 'select',
    header: ({ table }) => (
      <input
        type="checkbox"
        checked={table.getIsAllRowsSelected()}
        onChange={table.getToggleAllRowsSelectedHandler()}
        className="rounded border-slate-400 dark:border-slate-600"
      />
    ),
    cell: ({ row }) => (
      <input
        type="checkbox"
        checked={row.getIsSelected()}
        onChange={row.getToggleSelectedHandler()}
        className="rounded border-slate-400 dark:border-slate-600"
      />
    ),
    size: 40,
    enableSorting: false,
  },
  {
    accessorKey: 'severity',
    header: 'Severity',
    cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
    size: 100,
    sortingFn: (a, b) => (severityOrder[a.original.severity] ?? 99) - (severityOrder[b.original.severity] ?? 99),
  },
  {
    accessorKey: 'timestamp',
    header: 'Time',
    cell: ({ getValue }) => (
      <span className="text-sm text-slate-600 dark:text-slate-300" title={new Date(getValue()).toLocaleString()}>
        {formatTimestamp(getValue())}
      </span>
    ),
    size: 100,
  },
  {
    accessorKey: 'ruleName',
    header: 'Rule Name',
    cell: ({ getValue }) => (
      <span className="text-sm font-medium text-slate-800 dark:text-slate-200 truncate block max-w-[200px]" title={getValue()}>
        {getValue()}
      </span>
    ),
    size: 220,
  },
  {
    accessorKey: 'sourceIp',
    header: 'Source IP',
    cell: ({ getValue }) => (
      <span className="text-sm font-mono text-slate-600 dark:text-slate-300">{getValue() || '—'}</span>
    ),
    size: 130,
  },
  {
    accessorKey: 'destinationIp',
    header: 'Dest IP',
    cell: ({ getValue }) => (
      <span className="text-sm font-mono text-slate-600 dark:text-slate-300">{getValue() || '—'}</span>
    ),
    size: 130,
  },
  {
    accessorKey: 'user',
    header: 'User',
    cell: ({ getValue }) => (
      <span className="text-sm text-slate-600 dark:text-slate-300">{getValue() || '—'}</span>
    ),
    size: 100,
  },
  {
    accessorKey: 'mitreTactic',
    header: 'MITRE Tactic',
    cell: ({ getValue }) => (
      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300">
        {getValue()}
      </span>
    ),
    size: 140,
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ getValue }) => <StatusBadge status={getValue()} />,
    size: 120,
  },
  {
    accessorKey: 'assignee',
    header: 'Assignee',
    cell: ({ getValue }) => (
      <span className="text-sm text-slate-500 dark:text-slate-400">{getValue() || 'Unassigned'}</span>
    ),
    size: 100,
  },
]

function FilterDropdown({ label, value, options, onChange }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="px-2.5 py-1.5 rounded-lg text-sm border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300"
    >
      <option value="">{label}</option>
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>{opt.label}</option>
      ))}
    </select>
  )
}

export default function Alerts() {
  const [data, setData] = useState(mockAlerts)
  const [sorting, setSorting] = useState([{ id: 'timestamp', desc: true }])
  const [rowSelection, setRowSelection] = useState({})
  const [selectedAlert, setSelectedAlert] = useState(null)

  // Filters
  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [tacticFilter, setTacticFilter] = useState('')

  const filteredData = useMemo(() => {
    let result = data
    if (statusFilter) result = result.filter((a) => a.status === statusFilter)
    if (severityFilter) result = result.filter((a) => a.severity === severityFilter)
    if (tacticFilter) result = result.filter((a) => a.mitreTactic === tacticFilter)
    return result
  }, [data, statusFilter, severityFilter, tacticFilter])

  const tactics = useMemo(() => {
    const unique = [...new Set(data.map((a) => a.mitreTactic))]
    return unique.sort().map((t) => ({ value: t, label: t }))
  }, [data])

  const table = useReactTable({
    data: filteredData,
    columns,
    state: { sorting, rowSelection },
    onSortingChange: setSorting,
    onRowSelectionChange: setRowSelection,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId: (row) => row.id,
  })

  const selectedCount = Object.keys(rowSelection).length

  function handleAcknowledge(id) {
    setData((prev) => prev.map((a) => a.id === id ? { ...a, status: 'acknowledged' } : a))
    setSelectedAlert((prev) => prev && prev.id === id ? { ...prev, status: 'acknowledged' } : prev)
  }

  function handleEscalate(id) {
    setData((prev) => prev.map((a) => a.id === id ? { ...a, status: 'escalated' } : a))
    setSelectedAlert((prev) => prev && prev.id === id ? { ...prev, status: 'escalated' } : prev)
  }

  function handleCloseAlert(id) {
    setData((prev) => prev.map((a) => a.id === id ? { ...a, status: 'closed' } : a))
    setSelectedAlert((prev) => prev && prev.id === id ? { ...prev, status: 'closed' } : prev)
  }

  function handleBulkAcknowledge() {
    const ids = new Set(Object.keys(rowSelection))
    setData((prev) => prev.map((a) => ids.has(a.id) && a.status === 'new' ? { ...a, status: 'acknowledged' } : a))
    setRowSelection({})
  }

  function handleBulkClose() {
    const ids = new Set(Object.keys(rowSelection))
    setData((prev) => prev.map((a) => ids.has(a.id) && a.status !== 'closed' ? { ...a, status: 'closed' } : a))
    setRowSelection({})
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <BellAlertIcon className="h-7 w-7 text-indigo-400" />
          <h1 className="text-2xl font-semibold">Alerts</h1>
          <span className="text-sm text-slate-500 dark:text-slate-400">({filteredData.length})</span>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <FunnelIcon className="h-4 w-4 text-slate-400" />
        <FilterDropdown
          label="All Statuses"
          value={statusFilter}
          onChange={setStatusFilter}
          options={[
            { value: 'new', label: 'New' },
            { value: 'acknowledged', label: 'Acknowledged' },
            { value: 'in_progress', label: 'In Progress' },
            { value: 'escalated', label: 'Escalated' },
            { value: 'closed', label: 'Closed' },
          ]}
        />
        <FilterDropdown
          label="All Severities"
          value={severityFilter}
          onChange={setSeverityFilter}
          options={[
            { value: 'critical', label: 'Critical' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low' },
          ]}
        />
        <FilterDropdown
          label="All Tactics"
          value={tacticFilter}
          onChange={setTacticFilter}
          options={tactics}
        />
        {(statusFilter || severityFilter || tacticFilter) && (
          <button
            onClick={() => { setStatusFilter(''); setSeverityFilter(''); setTacticFilter('') }}
            className="text-xs text-indigo-400 hover:text-indigo-300"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id} className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
                  {headerGroup.headers.map((header) => (
                    <th
                      key={header.id}
                      onClick={header.column.getCanSort() ? header.column.getToggleSortingHandler() : undefined}
                      className={`px-3 py-2.5 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider ${
                        header.column.getCanSort() ? 'cursor-pointer select-none hover:text-slate-700 dark:hover:text-slate-200' : ''
                      }`}
                      style={{ width: header.getSize() }}
                    >
                      <div className="flex items-center gap-1">
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        {header.column.getIsSorted() === 'asc' && ' ↑'}
                        {header.column.getIsSorted() === 'desc' && ' ↓'}
                      </div>
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  onClick={() => setSelectedAlert(row.original)}
                  className={`cursor-pointer transition-colors border-l-[3px] ${
                    getSeverityBorderClass(row.original.severity)
                  } ${
                    selectedAlert?.id === row.id
                      ? 'bg-indigo-50 dark:bg-indigo-500/10'
                      : 'bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                  }`}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td
                      key={cell.id}
                      className="px-3 py-2.5 whitespace-nowrap"
                      onClick={cell.column.id === 'select' ? (e) => e.stopPropagation() : undefined}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
              {table.getRowModel().rows.length === 0 && (
                <tr>
                  <td colSpan={columns.length} className="px-4 py-8 text-center text-slate-400">
                    No alerts match the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bulk actions bar */}
      {selectedCount > 0 && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-30 flex items-center gap-3 px-4 py-3 rounded-xl bg-slate-800 dark:bg-slate-700 text-white shadow-2xl border border-slate-600">
          <span className="text-sm font-medium">{selectedCount} alert{selectedCount > 1 ? 's' : ''} selected</span>
          <div className="h-4 w-px bg-slate-600" />
          <button onClick={handleBulkAcknowledge} className="text-sm px-3 py-1 rounded-md hover:bg-slate-700 dark:hover:bg-slate-600 transition-colors">
            Acknowledge
          </button>
          <button onClick={handleBulkClose} className="text-sm px-3 py-1 rounded-md hover:bg-slate-700 dark:hover:bg-slate-600 transition-colors">
            Close
          </button>
          <button onClick={() => setRowSelection({})} className="text-sm px-3 py-1 rounded-md text-slate-400 hover:text-white transition-colors">
            Cancel
          </button>
        </div>
      )}

      {/* Flyout */}
      <AlertFlyout
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onAcknowledge={handleAcknowledge}
        onEscalate={handleEscalate}
        onCloseAlert={handleCloseAlert}
      />

      {/* Backdrop for flyout */}
      {selectedAlert && (
        <div
          className="fixed inset-0 z-30 bg-black/20 lg:hidden"
          onClick={() => setSelectedAlert(null)}
        />
      )}
    </div>
  )
}
