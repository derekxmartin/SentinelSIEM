import { useEffect, useRef, useCallback } from 'react'
import { api } from '../lib/api'
import { useSearchStore } from '../stores/searchStore'
import { detectEntity } from './useEntityDetector'
import { mockAlerts } from '../data/mockAlerts'
import { mockCases } from '../data/mockCases'
import { mockRules } from '../data/mockRules'

/**
 * Hook that manages debounced global search API calls with mock fallback.
 */
export default function useGlobalSearch() {
  const { query, setResults, setLoading } = useSearchStore()
  const timerRef = useRef(null)
  const abortRef = useRef(null)

  const performSearch = useCallback(async (q) => {
    if (!q.trim()) {
      setResults(null)
      return
    }

    const entity = detectEntity(q)
    if (!entity) return

    setLoading(true)

    // Cancel previous in-flight request.
    if (abortRef.current) abortRef.current.abort()
    const controller = new AbortController()
    abortRef.current = controller

    try {
      const data = await api.post('/search', {
        query: q.trim(),
        entity_type: entity.type,
      })
      if (!controller.signal.aborted) {
        // If API returned all-empty results, augment with mock data.
        const hasResults = (data.host_scores?.length > 0) ||
          data.alerts?.total > 0 || data.cases?.total > 0 ||
          data.events?.total > 0 || data.rules?.length > 0
        if (hasResults) {
          setResults(data)
        } else {
          setResults(searchMockData(q.trim(), entity.type))
        }
      }
    } catch {
      // Fallback to mock data search when API is unavailable.
      if (!controller.signal.aborted) {
        setResults(searchMockData(q.trim(), entity.type))
      }
    } finally {
      if (!controller.signal.aborted) {
        setLoading(false)
      }
    }
  }, [setResults, setLoading])

  // Debounce search by 200ms.
  useEffect(() => {
    clearTimeout(timerRef.current)
    if (!query.trim()) {
      setResults(null)
      setLoading(false)
      return
    }
    timerRef.current = setTimeout(() => performSearch(query), 200)
    return () => clearTimeout(timerRef.current)
  }, [query, performSearch, setResults, setLoading])

  return null
}

// --- Mock data fallback for development ---

function searchMockData(query, entityType) {
  const q = query.toLowerCase()

  const matchingAlerts = mockAlerts
    .filter(a => {
      if (entityType === 'ip') {
        return a.sourceIp === query || a.destinationIp === query
      }
      if (entityType === 'username') {
        return a.user?.toLowerCase() === q
      }
      return a.ruleName?.toLowerCase().includes(q) ||
        a.sourceIp?.includes(query) ||
        a.destinationIp?.includes(query) ||
        a.user?.toLowerCase().includes(q)
    })
    .slice(0, 5)
    .map(a => ({
      id: a.id,
      severity: a.severity,
      rule_name: a.ruleName,
      timestamp: a.timestamp,
    }))

  const matchingCases = mockCases
    .filter(c =>
      c.title?.toLowerCase().includes(q) ||
      c.tags?.some(t => t.toLowerCase().includes(q))
    )
    .slice(0, 5)
    .map(c => ({
      id: c.id,
      title: c.title,
      severity: c.severity,
      status: c.status,
    }))

  const matchingRules = mockRules
    .filter(r =>
      r.name?.toLowerCase().includes(q) ||
      r.description?.toLowerCase().includes(q)
    )
    .slice(0, 10)
    .map(r => ({
      id: r.id,
      name: r.name,
      description: r.description,
      severity: r.severity,
    }))

  return {
    host_scores: [],
    alerts: { total: matchingAlerts.length, items: matchingAlerts },
    cases: { total: matchingCases.length, items: matchingCases },
    events: { total: 0, by_source: {} },
    rules: matchingRules,
  }
}
