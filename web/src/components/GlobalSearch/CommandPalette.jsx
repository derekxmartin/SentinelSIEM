import { useNavigate } from 'react-router-dom'
import {
  ChartBarIcon,
  ShieldExclamationIcon,
  FolderIcon,
  MagnifyingGlassIcon,
  DocumentTextIcon,
  ServerIcon,
  Cog6ToothIcon,
  ArrowRightStartOnRectangleIcon,
  SunIcon,
  MoonIcon,
  SparklesIcon,
} from '@heroicons/react/24/outline'
import { useThemeStore } from '../../stores/themeStore'
import { useAuthStore } from '../../stores/authStore'

const commands = [
  { id: 'overview', label: 'Overview', keywords: ['dashboard', 'home'], icon: ChartBarIcon, path: '/' },
  { id: 'alerts', label: 'Alerts', keywords: ['triage', 'alert'], icon: ShieldExclamationIcon, path: '/alerts' },
  { id: 'cases', label: 'Cases', keywords: ['case', 'incident'], icon: FolderIcon, path: '/cases' },
  { id: 'hunt', label: 'Hunt', keywords: ['search', 'query', 'investigate'], icon: MagnifyingGlassIcon, path: '/hunt' },
  { id: 'rules', label: 'Rules', keywords: ['sigma', 'detection'], icon: DocumentTextIcon, path: '/rules' },
  { id: 'sources', label: 'Sources', keywords: ['source', 'data', 'ingest'], icon: ServerIcon, path: '/sources' },
  { id: 'settings', label: 'Settings', keywords: ['config', 'profile', 'preferences'], icon: Cog6ToothIcon, path: '/settings' },
  { id: 'dark', label: 'Dark mode', keywords: ['theme', 'dark'], icon: MoonIcon, action: 'dark' },
  { id: 'light', label: 'Light mode', keywords: ['theme', 'light'], icon: SunIcon, action: 'light' },
  { id: 'ai', label: 'AI Assistant', keywords: ['assistant', 'investigate'], icon: SparklesIcon, action: 'ai' },
  { id: 'logout', label: 'Sign out', keywords: ['logout', 'signout'], icon: ArrowRightStartOnRectangleIcon, action: 'logout' },
]

export default function CommandPalette({ query, selectedIndex, onClose }) {
  const navigate = useNavigate()
  const setTheme = useThemeStore((s) => s.setTheme)
  const logout = useAuthStore((s) => s.logout)

  // Strip leading "/" for matching.
  const q = query.replace(/^\//, '').toLowerCase().trim()

  const filtered = q
    ? commands.filter(c =>
        c.label.toLowerCase().includes(q) ||
        c.id.includes(q) ||
        c.keywords.some(k => k.includes(q))
      )
    : commands

  function execute(cmd) {
    if (cmd.path) {
      navigate(cmd.path)
    } else if (cmd.action === 'dark') {
      setTheme('dark')
    } else if (cmd.action === 'light') {
      setTheme('light')
    } else if (cmd.action === 'logout') {
      logout()
    }
    onClose()
  }

  if (filtered.length === 0) {
    return (
      <div className="p-4 text-center text-sm text-slate-500">
        No commands found
      </div>
    )
  }

  return (
    <div className="p-1">
      {filtered.map((cmd, i) => {
        const Icon = cmd.icon
        return (
          <button
            key={cmd.id}
            onClick={() => execute(cmd)}
            className={`flex items-center gap-3 w-full px-3 py-2 text-left text-sm rounded-md transition-colors ${
              i === selectedIndex
                ? 'bg-indigo-600/20 text-indigo-300'
                : 'text-slate-300 hover:bg-slate-700/50'
            }`}
          >
            <Icon className="h-4 w-4 shrink-0 text-slate-400" />
            <span>{cmd.label}</span>
            {cmd.path && (
              <span className="ml-auto text-xs text-slate-500">{cmd.path}</span>
            )}
          </button>
        )
      })}
    </div>
  )
}

// Export for keyboard navigation count.
export function getFilteredCommandCount(query) {
  const q = query.replace(/^\//, '').toLowerCase().trim()
  if (!q) return commands.length
  return commands.filter(c =>
    c.label.toLowerCase().includes(q) ||
    c.id.includes(q) ||
    c.keywords.some(k => k.includes(q))
  ).length
}
