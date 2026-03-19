import { XMarkIcon, ClockIcon } from '@heroicons/react/24/outline'

const STORAGE_KEY_PREFIX = 'akeso-recent-searches-'

export function getRecentSearches(username) {
  try {
    const raw = localStorage.getItem(STORAGE_KEY_PREFIX + (username || 'anon'))
    return raw ? JSON.parse(raw) : []
  } catch {
    return []
  }
}

export function addRecentSearch(username, entry) {
  const key = STORAGE_KEY_PREFIX + (username || 'anon')
  const existing = getRecentSearches(username)
  // Remove duplicate, prepend new, cap at 10.
  const filtered = existing.filter(e => e.query !== entry.query)
  const updated = [entry, ...filtered].slice(0, 10)
  try {
    localStorage.setItem(key, JSON.stringify(updated))
  } catch {}
}

export function removeRecentSearch(username, query) {
  const key = STORAGE_KEY_PREFIX + (username || 'anon')
  const existing = getRecentSearches(username)
  const updated = existing.filter(e => e.query !== query)
  try {
    localStorage.setItem(key, JSON.stringify(updated))
  } catch {}
}

export function clearRecentSearches(username) {
  try {
    localStorage.removeItem(STORAGE_KEY_PREFIX + (username || 'anon'))
  } catch {}
}

export default function RecentSearches({ username, onSelect, onClear }) {
  const items = getRecentSearches(username)
  if (items.length === 0) return null

  return (
    <div className="p-2">
      <div className="flex items-center justify-between px-2 mb-1">
        <span className="text-xs font-medium text-slate-400 uppercase">Recent searches</span>
        <button
          onClick={() => onClear()}
          className="text-xs text-slate-400 hover:text-slate-300"
        >
          Clear all
        </button>
      </div>
      {items.map((item) => (
        <button
          key={item.query}
          onClick={() => onSelect(item.query)}
          className="flex items-center gap-2 w-full px-2 py-1.5 text-left text-sm text-slate-300 hover:bg-slate-700/50 rounded"
        >
          <ClockIcon className="h-3.5 w-3.5 text-slate-500 shrink-0" />
          <span className="truncate flex-1">{item.query}</span>
          {item.entityLabel && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700 text-slate-400">{item.entityLabel}</span>
          )}
          <XMarkIcon
            className="h-3.5 w-3.5 text-slate-500 hover:text-slate-300 shrink-0"
            onClick={(e) => {
              e.stopPropagation()
              onClear(item.query)
            }}
          />
        </button>
      ))}
    </div>
  )
}
