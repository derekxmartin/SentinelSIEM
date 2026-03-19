import { NavLink } from 'react-router-dom'
import logo from '../assets/logo.svg'
import { Dialog, DialogBackdrop, DialogPanel } from '@headlessui/react'
import {
  HomeIcon,
  BellAlertIcon,
  FolderOpenIcon,
  MagnifyingGlassIcon,
  ShieldCheckIcon,
  ServerStackIcon,
  Cog6ToothIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline'

const navItems = [
  { to: '/', label: 'Overview', icon: HomeIcon, end: true },
  { to: '/alerts', label: 'Alerts', icon: BellAlertIcon },
  { to: '/cases', label: 'Cases', icon: FolderOpenIcon },
  { to: '/hunt', label: 'Hunt', icon: MagnifyingGlassIcon },
  { to: '/rules', label: 'Rules', icon: ShieldCheckIcon },
  { to: '/sources', label: 'Sources', icon: ServerStackIcon },
  { to: '/settings', label: 'Settings', icon: Cog6ToothIcon },
]

function NavItem({ item, collapsed }) {
  return (
    <NavLink
      to={item.to}
      end={item.end}
      className={({ isActive }) =>
        `flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors ${
          collapsed ? 'justify-center' : ''
        } ${
          isActive
            ? 'bg-indigo-500/10 text-indigo-400 border-l-2 border-indigo-500 -ml-px'
            : 'text-slate-300 hover:bg-slate-700/50 hover:text-white'
        }`
      }
    >
      <item.icon className="h-5 w-5 shrink-0" />
      {!collapsed && <span>{item.label}</span>}
    </NavLink>
  )
}

function SidebarContent({ collapsed, onToggle, onClose }) {
  return (
    <div className="flex flex-col h-full" style={{ backgroundColor: '#0D0608' }}>
      {/* Logo */}
      <div className={`flex items-center justify-center h-16 px-4 border-b border-slate-700/50 ${collapsed ? 'px-2' : ''}`}>
        <NavLink to="/" className="flex items-center gap-2 min-w-0">
          <img src={logo} alt="AkesoSIEM" className={`shrink-0 transition-all ${collapsed ? 'h-10 w-10' : 'h-9 w-9'}`} />
          {!collapsed && (
            <span className="text-white font-semibold text-lg truncate">AkesoSIEM</span>
          )}
        </NavLink>
        {/* Mobile close button */}
        {onClose && (
          <button onClick={onClose} className="ml-auto text-slate-400 hover:text-white lg:hidden">
            <XMarkIcon className="h-5 w-5" />
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => (
          <NavItem key={item.to} item={item} collapsed={collapsed} />
        ))}
      </nav>

      {/* Collapse toggle (desktop only) */}
      <div className="hidden lg:block px-3 py-3 border-t border-slate-700/50">
        <button
          onClick={onToggle}
          className="flex items-center justify-center w-full py-2 rounded-md text-slate-400 hover:text-white hover:bg-slate-700/50 transition-colors"
        >
          {collapsed ? (
            <ChevronRightIcon className="h-5 w-5" />
          ) : (
            <ChevronLeftIcon className="h-5 w-5" />
          )}
        </button>
      </div>
    </div>
  )
}

export default function Sidebar({ collapsed, onToggle, mobileOpen, onMobileClose }) {
  return (
    <>
      {/* Desktop sidebar */}
      <aside
        className={`hidden lg:flex flex-col shrink-0 transition-all duration-300 ${
          collapsed ? 'w-16' : 'w-64'
        }`}
      >
        <SidebarContent collapsed={collapsed} onToggle={onToggle} />
      </aside>

      {/* Mobile sidebar overlay */}
      <Dialog open={mobileOpen} onClose={onMobileClose} className="lg:hidden">
        <DialogBackdrop className="fixed inset-0 bg-black/50 z-40" />
        <DialogPanel className="fixed inset-y-0 left-0 z-50 w-64">
          <SidebarContent collapsed={false} onClose={onMobileClose} />
        </DialogPanel>
      </Dialog>
    </>
  )
}
