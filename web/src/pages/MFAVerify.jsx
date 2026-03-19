import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldCheckIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline'
import { useAuthStore } from '../stores/authStore'
import logo from '../assets/logo.svg'
import usePageTitle from '../hooks/usePageTitle'

export default function MFAVerify() {
  usePageTitle('Verify MFA')
  const navigate = useNavigate()
  const verifyMFA = useAuthStore((s) => s.verifyMFA)
  const mfaPending = useAuthStore((s) => s.mfaPending)
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)

  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const inputRef = useRef(null)

  // Redirect if no MFA challenge pending.
  useEffect(() => {
    if (!mfaPending) navigate('/login', { replace: true })
  }, [mfaPending, navigate])

  // Redirect on successful auth.
  useEffect(() => {
    if (isAuthenticated) navigate('/', { replace: true })
  }, [isAuthenticated, navigate])

  // Auto-submit when 6 digits entered.
  useEffect(() => {
    if (code.length === 6) handleSubmit()
  }, [code])

  const handleSubmit = async (e) => {
    if (e) e.preventDefault()
    if (code.length !== 6 || loading) return

    setLoading(true)
    setError('')

    try {
      await verifyMFA(code)
    } catch (err) {
      setError(err.status === 401 ? 'Invalid code. Please try again.' : 'Verification failed')
      setCode('')
      inputRef.current?.focus()
    } finally {
      setLoading(false)
    }
  }

  const handleChange = (e) => {
    const val = e.target.value.replace(/\D/g, '').slice(0, 6)
    setCode(val)
    setError('')
  }

  const handleBack = () => {
    useAuthStore.getState().clearAuth()
    navigate('/login', { replace: true })
  }

  if (!mfaPending) return null

  return (
    <div className="min-h-screen flex items-center justify-center px-4" style={{ backgroundColor: '#0D0608' }}>
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <img src={logo} alt="AkesoSIEM" className="h-16 w-16 mb-4" />
          <ShieldCheckIcon className="h-10 w-10 text-indigo-400 mb-2" />
          <h1 className="text-xl font-bold text-white">Two-Factor Authentication</h1>
          <p className="text-slate-400 text-sm mt-1 text-center">
            Enter the 6-digit code from your authenticator app
          </p>
        </div>

        <form onSubmit={handleSubmit} className="bg-slate-900 rounded-xl border border-slate-700/50 p-6 space-y-4">
          {error && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
              <ExclamationTriangleIcon className="h-5 w-5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <input
              ref={inputRef}
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              autoComplete="one-time-code"
              autoFocus
              value={code}
              onChange={handleChange}
              maxLength={6}
              className="w-full px-4 py-3 rounded-lg bg-slate-800 border border-slate-600 text-white text-center text-2xl font-mono tracking-[0.5em] focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent placeholder-slate-600"
              placeholder="000000"
            />
          </div>

          <button
            type="submit"
            disabled={code.length !== 6 || loading}
            className="w-full py-2.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-medium text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Verifying...' : 'Verify'}
          </button>

          <button
            type="button"
            onClick={handleBack}
            className="w-full text-sm text-slate-400 hover:text-slate-300 transition-colors"
          >
            Back to sign in
          </button>
        </form>
      </div>
    </div>
  )
}
