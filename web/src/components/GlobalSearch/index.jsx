import { useRef, useEffect, useCallback } from 'react'
import { useSearchStore } from '../../stores/searchStore'
import { useAuthStore } from '../../stores/authStore'
import useGlobalSearch from '../../hooks/useGlobalSearch'
import { detectEntity } from '../../hooks/useEntityDetector'
import SearchInput from './SearchInput'
import SearchDropdown from './SearchDropdown'
import EntityResults from './EntityResults'
import CommandPalette, { getFilteredCommandCount } from './CommandPalette'
import RecentSearches, { addRecentSearch, removeRecentSearch, clearRecentSearches } from './RecentSearches'

export default function GlobalSearch() {
  const inputRef = useRef(null)
  const containerRef = useRef(null)
  const { isOpen, mode, query, results, isLoading, selectedIndex, setOpen, setMode, setQuery, setSelectedIndex, reset } = useSearchStore()
  const username = useAuthStore((s) => s.user?.username)

  // Drive the debounced search hook.
  useGlobalSearch()

  // Close on click outside.
  useEffect(() => {
    function handleClickOutside(e) {
      if (containerRef.current && !containerRef.current.contains(e.target)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [setOpen])

  // Global keyboard shortcuts.
  useEffect(() => {
    function handleGlobalKey(e) {
      // Cmd+/ or Ctrl+/ — focus entity search.
      if ((e.metaKey || e.ctrlKey) && e.key === '/') {
        e.preventDefault()
        setMode('entity')
        setOpen(true)
        inputRef.current?.focus()
      }
      // Cmd+Shift+P or Ctrl+Shift+P — command palette.
      if ((e.metaKey || e.ctrlKey) && e.shiftKey && e.key === 'P') {
        e.preventDefault()
        setMode('command')
        setQuery('/')
        setOpen(true)
        inputRef.current?.focus()
      }
    }
    document.addEventListener('keydown', handleGlobalKey)
    return () => document.removeEventListener('keydown', handleGlobalKey)
  }, [setMode, setOpen, setQuery])

  const close = useCallback(() => {
    setOpen(false)
    inputRef.current?.blur()
  }, [setOpen])

  function handleInputChange(e) {
    const val = e.target.value
    setQuery(val)
    setOpen(true)

    // Auto-detect command mode.
    if (val.startsWith('/') && mode !== 'command') {
      setMode('command')
    } else if (!val.startsWith('/') && mode === 'command') {
      setMode('entity')
    }
  }

  function handleFocus() {
    setOpen(true)
  }

  function handleKeyDown(e) {
    if (e.key === 'Escape') {
      close()
      return
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSelectedIndex(Math.min(selectedIndex + 1, getMaxIndex() - 1))
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSelectedIndex(Math.max(selectedIndex - 1, -1))
    }

    if (e.key === 'Enter' && mode === 'entity' && query.trim() && selectedIndex === -1) {
      // Save to recent searches and keep dropdown open for results.
      const entity = detectEntity(query)
      addRecentSearch(username, { query: query.trim(), entityLabel: entity?.label })
    }
  }

  function handleRecentSelect(q) {
    setQuery(q)
    setMode('entity')
    inputRef.current?.focus()
  }

  function handleClearRecent(specificQuery) {
    if (specificQuery) {
      removeRecentSearch(username, specificQuery)
    } else {
      clearRecentSearches(username)
    }
    // Force re-render by toggling.
    setOpen(false)
    setTimeout(() => setOpen(true), 0)
  }

  function getMaxIndex() {
    if (mode === 'command') return getFilteredCommandCount(query)
    return 0 // Entity results use their own click handlers.
  }

  // Determine what to show in dropdown.
  const showRecent = isOpen && mode === 'entity' && !query.trim()
  const showEntityResults = isOpen && mode === 'entity' && query.trim() && results
  const showCommandPalette = isOpen && mode === 'command'
  const showLoading = isOpen && mode === 'entity' && query.trim() && isLoading && !results
  const showDropdown = showRecent || showEntityResults || showCommandPalette || showLoading

  return (
    <div ref={containerRef} className="flex-1 max-w-2xl relative">
      <SearchInput
        ref={inputRef}
        value={query}
        onChange={handleInputChange}
        onKeyDown={handleKeyDown}
        onFocus={handleFocus}
        mode={mode}
      />

      <SearchDropdown isOpen={showDropdown}>
        {showLoading && (
          <div className="p-4 text-center text-sm text-slate-500">
            Searching...
          </div>
        )}

        {showRecent && (
          <RecentSearches
            username={username}
            onSelect={handleRecentSelect}
            onClear={handleClearRecent}
          />
        )}

        {showEntityResults && (
          <EntityResults results={results} query={query} onClose={close} />
        )}

        {showCommandPalette && (
          <CommandPalette query={query} selectedIndex={selectedIndex} onClose={close} />
        )}
      </SearchDropdown>
    </div>
  )
}
