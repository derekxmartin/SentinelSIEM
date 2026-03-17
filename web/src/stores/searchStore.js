import { create } from 'zustand'

export const useSearchStore = create((set) => ({
  isOpen: false,
  mode: 'entity', // 'entity' | 'command'
  query: '',
  results: null,
  isLoading: false,
  selectedIndex: -1,

  setOpen: (isOpen) => set({ isOpen }),
  setMode: (mode) => set({ mode, selectedIndex: -1 }),
  setQuery: (query) => set({ query }),
  setResults: (results) => set({ results }),
  setLoading: (isLoading) => set({ isLoading }),
  setSelectedIndex: (selectedIndex) => set({ selectedIndex }),
  reset: () => set({ isOpen: false, query: '', results: null, isLoading: false, selectedIndex: -1, mode: 'entity' }),
}))
