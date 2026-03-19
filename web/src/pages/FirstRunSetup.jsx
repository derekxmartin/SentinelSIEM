import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { ExclamationTriangleIcon, CheckCircleIcon } from '@heroicons/react/24/outline'
import { apiFetch } from '../lib/api'
import logo from '../assets/logo.svg'
import usePageTitle from '../hooks/usePageTitle'

export default function FirstRunSetup() {
  usePageTitle('Setup')
  const navigate = useNavigate()

  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [loading, setLoading] = useState(false)
  const [checking, setChecking] = useState(true)

  // Verify setup is actually required.
  useEffect(() => {
    apiFetch('/auth/setup-required', { method: 'GET' })
      .then((data) => {
        if (!data.setup_required) navigate('/login', { replace: true })
        else setChecking(false)
      })
      .catch(() => setChecking(false))
  }, [navigate])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')

    if (!username.trim() || !displayName.trim() || !password) {
      setError('Username, display name, and password are required')
      return
    }
    if (username.trim().length < 3) {
      setError('Username must be at least 3 characters')
      return
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters')
      return
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setLoading(true)
    try {
      await apiFetch('/auth/setup', {
        method: 'POST',
        body: JSON.stringify({
          username: username.trim(),
          display_name: displayName.trim(),
          email: email.trim() || undefined,
          password,
        }),
      })
      setSuccess(true)
      setTimeout(() => navigate('/login', { replace: true }), 2000)
    } catch (err) {
      if (err.status === 409) {
        navigate('/login', { replace: true })
      } else {
        setError(err.message || 'Setup failed')
      }
    } finally {
      setLoading(false)
    }
  }

  if (checking) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: '#0D0608' }}>
        <img src={logo} alt="AkesoSIEM" className="h-16 w-16 animate-pulse" />
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4" style={{ backgroundColor: '#0D0608' }}>
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <img src={logo} alt="AkesoSIEM" className="h-16 w-16 mb-4" />
          <h1 className="text-2xl font-bold text-white">Welcome to AkesoSIEM</h1>
          <p className="text-slate-400 text-sm mt-1">Create your admin account to get started</p>
        </div>

        {success ? (
          <div className="bg-slate-900 rounded-xl border border-slate-700/50 p-6">
            <div className="flex flex-col items-center gap-3 text-center">
              <CheckCircleIcon className="h-12 w-12 text-green-400" />
              <h2 className="text-lg font-semibold text-white">Account Created</h2>
              <p className="text-slate-400 text-sm">Redirecting to sign in...</p>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="bg-slate-900 rounded-xl border border-slate-700/50 p-6 space-y-4">
            {error && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                <ExclamationTriangleIcon className="h-5 w-5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <div>
              <label htmlFor="setup-username" className="block text-sm font-medium text-slate-300 mb-1.5">
                Username
              </label>
              <input
                id="setup-username"
                type="text"
                autoComplete="username"
                autoFocus
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-600 text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                placeholder="admin"
              />
            </div>

            <div>
              <label htmlFor="setup-display" className="block text-sm font-medium text-slate-300 mb-1.5">
                Display Name
              </label>
              <input
                id="setup-display"
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-600 text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                placeholder="Admin User"
              />
            </div>

            <div>
              <label htmlFor="setup-email" className="block text-sm font-medium text-slate-300 mb-1.5">
                Email <span className="text-slate-500">(optional)</span>
              </label>
              <input
                id="setup-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-600 text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                placeholder="admin@example.com"
              />
            </div>

            <div>
              <label htmlFor="setup-password" className="block text-sm font-medium text-slate-300 mb-1.5">
                Password
              </label>
              <input
                id="setup-password"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-600 text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                placeholder="Minimum 8 characters"
              />
            </div>

            <div>
              <label htmlFor="setup-confirm" className="block text-sm font-medium text-slate-300 mb-1.5">
                Confirm Password
              </label>
              <input
                id="setup-confirm"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-800 border border-slate-600 text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                placeholder="Confirm password"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Creating account...' : 'Create Admin Account'}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
