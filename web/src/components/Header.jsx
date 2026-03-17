import { Bars3Icon, SparklesIcon } from '@heroicons/react/24/outline'
import ThemeToggle from './ThemeToggle'
import UserMenu from './UserMenu'
import GlobalSearch from './GlobalSearch'

export default function Header({ onMobileMenuToggle }) {
  return (
    <header className="sticky top-0 z-30 h-16 flex items-center gap-4 px-4 border-b border-slate-200 bg-white/80 dark:border-slate-700 dark:bg-slate-900/80 backdrop-blur-md">
      {/* Mobile menu button */}
      <button
        onClick={onMobileMenuToggle}
        className="lg:hidden text-slate-400 hover:text-white"
      >
        <Bars3Icon className="h-6 w-6" />
      </button>

      {/* Global search */}
      <GlobalSearch />

      {/* Right section */}
      <div className="flex items-center gap-3 ml-auto">
        <ThemeToggle />

        {/* AI assistant placeholder */}
        <button className="text-slate-400 hover:text-indigo-400 transition-colors" title="AI Assistant">
          <SparklesIcon className="h-5 w-5" />
        </button>

        {/* User menu */}
        <UserMenu />
      </div>
    </header>
  )
}
