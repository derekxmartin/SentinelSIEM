const severityConfig = {
  critical: {
    label: 'Critical',
    badge: 'bg-red-500/20 text-red-400 border-red-500/30 dark:bg-red-500/20 dark:text-red-400 dark:border-red-500/30',
    badgeLight: 'bg-red-50 text-red-700 border-red-200',
    border: 'border-l-red-500',
  },
  high: {
    label: 'High',
    badge: 'bg-orange-500/20 text-orange-400 border-orange-500/30 dark:bg-orange-500/20 dark:text-orange-400 dark:border-orange-500/30',
    badgeLight: 'bg-orange-50 text-orange-700 border-orange-200',
    border: 'border-l-orange-500',
  },
  medium: {
    label: 'Medium',
    badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30 dark:bg-yellow-500/20 dark:text-yellow-300 dark:border-yellow-500/30',
    badgeLight: 'bg-yellow-50 text-yellow-700 border-yellow-200',
    border: 'border-l-yellow-500',
  },
  low: {
    label: 'Low',
    badge: 'bg-blue-500/20 text-blue-400 border-blue-500/30 dark:bg-blue-500/20 dark:text-blue-400 dark:border-blue-500/30',
    badgeLight: 'bg-blue-50 text-blue-700 border-blue-200',
    border: 'border-l-blue-500',
  },
}

export function getSeverityBorderClass(severity) {
  return severityConfig[severity]?.border || ''
}

export default function SeverityBadge({ severity }) {
  const config = severityConfig[severity] || severityConfig.low
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${config.badgeLight} dark:bg-opacity-100 ${config.badge}`}>
      {config.label}
    </span>
  )
}
