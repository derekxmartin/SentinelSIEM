import { forwardRef } from 'react'
import { MagnifyingGlassIcon, CommandLineIcon } from '@heroicons/react/24/outline'
import useEntityDetector from '../../hooks/useEntityDetector'

const SearchInput = forwardRef(function SearchInput({ value, onChange, onKeyDown, onFocus, mode }, ref) {
  const entity = useEntityDetector(value)
  const isCommand = mode === 'command'

  return (
    <div className="relative">
      {isCommand ? (
        <CommandLineIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-indigo-400" />
      ) : (
        <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
      )}
      <input
        ref={ref}
        type="text"
        value={value}
        onChange={onChange}
        onKeyDown={onKeyDown}
        onFocus={onFocus}
        placeholder={isCommand ? 'Type a command...' : 'Search entities, events, rules...'}
        className="w-full pl-9 pr-20 py-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-600 placeholder-slate-400 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300 dark:placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500"
      />
      <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1.5">
        {/* Entity type badge */}
        {!isCommand && entity && value.trim() && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-medium">
            {entity.label}
          </span>
        )}
        {/* Keyboard hint */}
        <kbd className="hidden sm:inline text-[10px] px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-700 text-slate-400 font-mono">
          {navigator.platform?.includes('Mac') ? '⌘/' : 'Ctrl+/'}
        </kbd>
      </div>
    </div>
  )
})

export default SearchInput
