import { create } from 'zustand'

const STORAGE_KEY = 'akeso-theme'

function getSystemPreference() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function resolveTheme(mode) {
  if (mode === 'system') return getSystemPreference()
  return mode
}

function applyTheme(resolved) {
  document.documentElement.classList.toggle('dark', resolved === 'dark')
}

const savedMode = (() => {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (stored === 'dark' || stored === 'light' || stored === 'system') return stored
  } catch {}
  return 'dark'
})()

const initialResolved = resolveTheme(savedMode)
applyTheme(initialResolved)

export const useThemeStore = create((set, get) => ({
  mode: savedMode,
  resolved: initialResolved,

  isDark: () => get().resolved === 'dark',

  setMode: (mode) => {
    const resolved = resolveTheme(mode)
    applyTheme(resolved)
    try { localStorage.setItem(STORAGE_KEY, mode) } catch {}
    set({ mode, resolved })
  },
}))

// Listen for system preference changes when in 'system' mode.
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  const { mode } = useThemeStore.getState()
  if (mode === 'system') {
    const resolved = getSystemPreference()
    applyTheme(resolved)
    useThemeStore.setState({ resolved })
  }
})
