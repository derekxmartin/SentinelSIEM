import { useMemo } from 'react'

const patterns = [
  { type: 'ip', label: 'IP', regex: /^(\d{1,3}\.){3}\d{1,3}$/ },
  { type: 'ip', label: 'IPv6', regex: /^[0-9a-fA-F:]{3,39}$/ },
  { type: 'sha256', label: 'SHA-256', regex: /^[0-9a-fA-F]{64}$/ },
  { type: 'sha1', label: 'SHA-1', regex: /^[0-9a-fA-F]{40}$/ },
  { type: 'md5_ja3', label: 'MD5', regex: /^[0-9a-fA-F]{32}$/ },
  { type: 'community_id', label: 'Community ID', regex: /^1:/ },
  { type: 'case_id', label: 'Case ID', regex: /^CASE-/i },
  { type: 'alert_id', label: 'Alert ID', regex: /^ALERT-/i },
  { type: 'path', label: 'Path', regex: /^[A-Za-z]:\\/ },
  { type: 'domain', label: 'Domain', regex: /^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$/ },
  { type: 'username', label: 'User', regex: /^[a-zA-Z][a-zA-Z0-9._-]{0,30}$/ },
]

/**
 * Detect entity type from a search query string.
 * Returns { type, label } or { type: 'freetext', label: 'Search' } as fallback.
 */
export function detectEntity(query) {
  const trimmed = query.trim()
  if (!trimmed) return null

  for (const p of patterns) {
    if (p.regex.test(trimmed)) {
      return { type: p.type, label: p.label }
    }
  }
  return { type: 'freetext', label: 'Search' }
}

/**
 * React hook that memoizes entity detection for a query string.
 */
export default function useEntityDetector(query) {
  return useMemo(() => detectEntity(query), [query])
}
