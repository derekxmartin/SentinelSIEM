import { useEffect } from 'react'
import { Outlet, Navigate, useLocation } from 'react-router-dom'
import { useAuthStore } from '../stores/authStore'
import logo from '../assets/logo.svg'

export default function AuthGuard() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const isLoading = useAuthStore((s) => s.isLoading)
  const silentRefresh = useAuthStore((s) => s.silentRefresh)
  const location = useLocation()

  // Attempt silent refresh on mount.
  useEffect(() => {
    silentRefresh()
  }, [])

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: '#0D0608' }}>
        <div className="flex flex-col items-center gap-4">
          <img src={logo} alt="AkesoSIEM" className="h-16 w-16 animate-pulse" />
          <p className="text-slate-400 text-sm">Loading...</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location.pathname }} replace />
  }

  return <Outlet />
}
