import { create } from 'zustand'
import { apiFetch } from '../lib/api'

const REFRESH_KEY = 'akeso-refresh-token'

let refreshTimer = null

function scheduleRefresh(expiresIn) {
  clearTimeout(refreshTimer)
  // Refresh 60s before expiry, minimum 5s.
  const ms = Math.max((expiresIn - 60) * 1000, 5000)
  refreshTimer = setTimeout(() => {
    useAuthStore.getState().silentRefresh()
  }, ms)
}

function loadRefreshToken() {
  try {
    return localStorage.getItem(REFRESH_KEY)
  } catch {
    return null
  }
}

function saveRefreshToken(token) {
  try {
    if (token) localStorage.setItem(REFRESH_KEY, token)
    else localStorage.removeItem(REFRESH_KEY)
  } catch {}
}

export const useAuthStore = create((set, get) => ({
  accessToken: null,
  refreshToken: loadRefreshToken(),
  user: null,
  isAuthenticated: false,
  isLoading: true,
  mfaPending: null,
  error: null,

  /**
   * Login with username/password.
   * Returns response — caller checks mfa_required.
   */
  login: async (username, password) => {
    set({ error: null })
    try {
      const data = await apiFetch('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      })

      if (data.mfa_required) {
        set({ mfaPending: { mfa_token: data.mfa_token } })
        return data
      }

      saveRefreshToken(data.refresh_token)
      scheduleRefresh(data.expires_in)
      set({
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        user: data.user,
        isAuthenticated: true,
        isLoading: false,
        mfaPending: null,
        error: null,
      })
      return data
    } catch (err) {
      set({ error: err.message })
      throw err
    }
  },

  /**
   * Complete MFA login challenge.
   */
  verifyMFA: async (code) => {
    const { mfaPending } = get()
    if (!mfaPending) throw new Error('No MFA challenge pending')

    set({ error: null })
    try {
      const data = await apiFetch('/auth/mfa', {
        method: 'POST',
        body: JSON.stringify({ mfa_token: mfaPending.mfa_token, code }),
      })

      saveRefreshToken(data.refresh_token)
      scheduleRefresh(data.expires_in)
      set({
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        user: data.user,
        isAuthenticated: true,
        isLoading: false,
        mfaPending: null,
        error: null,
      })
      return data
    } catch (err) {
      set({ error: err.message })
      throw err
    }
  },

  /**
   * Silent refresh using stored refresh token.
   */
  silentRefresh: async () => {
    const refreshToken = get().refreshToken || loadRefreshToken()
    if (!refreshToken) {
      set({ isLoading: false, isAuthenticated: false })
      return
    }

    try {
      const data = await apiFetch('/auth/refresh', {
        method: 'POST',
        body: JSON.stringify({ refresh_token: refreshToken }),
      })

      scheduleRefresh(data.expires_in)

      // Fetch full profile with the new token.
      const profile = await apiFetch('/auth/profile', {
        method: 'GET',
        headers: { Authorization: `Bearer ${data.access_token}` },
      })

      set({
        accessToken: data.access_token,
        refreshToken: refreshToken,
        user: profile,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      })
    } catch {
      saveRefreshToken(null)
      set({
        accessToken: null,
        refreshToken: null,
        user: null,
        isAuthenticated: false,
        isLoading: false,
      })
    }
  },

  /**
   * Logout — revoke session on server.
   */
  logout: async () => {
    const { refreshToken, accessToken } = get()
    clearTimeout(refreshTimer)

    try {
      if (refreshToken) {
        await apiFetch('/auth/logout', {
          method: 'POST',
          body: JSON.stringify({ refresh_token: refreshToken }),
          headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {},
        })
      }
    } catch {
      // Ignore logout errors.
    }

    saveRefreshToken(null)
    set({
      accessToken: null,
      refreshToken: null,
      user: null,
      isAuthenticated: false,
      isLoading: false,
      mfaPending: null,
      error: null,
    })
  },

  /**
   * Fetch and update user profile.
   */
  fetchProfile: async () => {
    const { accessToken } = get()
    if (!accessToken) return

    try {
      const profile = await apiFetch('/auth/profile', {
        method: 'GET',
        headers: { Authorization: `Bearer ${accessToken}` },
      })
      set({ user: profile })
    } catch {
      // Ignore — profile fetch is best-effort.
    }
  },

  /**
   * Clear auth state without server call (used on 401 in api client).
   */
  clearAuth: () => {
    clearTimeout(refreshTimer)
    saveRefreshToken(null)
    set({
      accessToken: null,
      refreshToken: null,
      user: null,
      isAuthenticated: false,
      isLoading: false,
      mfaPending: null,
    })
  },

  setUser: (user) => set({ user }),
}))
