const statusConfig = {
  new: { label: 'New', class: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  acknowledged: { label: 'Acknowledged', class: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30' },
  in_progress: { label: 'In Progress', class: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30' },
  escalated: { label: 'Escalated', class: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  closed: { label: 'Closed', class: 'bg-slate-500/20 text-slate-400 border-slate-500/30' },
}

export default function StatusBadge({ status }) {
  const config = statusConfig[status] || statusConfig.new
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${config.class}`}>
      {config.label}
    </span>
  )
}
