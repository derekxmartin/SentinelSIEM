// Mock hunt results for development. Will be replaced by API calls.

const now = Date.now()
const min = 60 * 1000
const hr = 60 * min

// ECS-style field names for autocomplete
export const fieldNames = [
  'source.ip', 'destination.ip', 'source.port', 'destination.port',
  'event.action', 'event.category', 'event.outcome', 'event.code',
  'user.name', 'user.domain',
  'process.name', 'process.pid', 'process.command_line', 'process.parent.name',
  'host.name', 'host.ip', 'host.os.name',
  'file.name', 'file.path', 'file.hash.sha256',
  'network.protocol', 'network.direction', 'network.bytes',
  'agent.name', 'agent.type',
  'log.level', 'message',
  '@timestamp',
]

function randomIp() {
  return `10.1.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 254) + 1}`
}

const actions = ['logon_success', 'logon_failure', 'process_create', 'file_access', 'network_connection', 'dns_query', 'registry_modify', 'service_install']
const users = ['jsmith', 'awhite', 'bking', 'mjones', 'svcadmin', 'admin', 'dbrown', 'cwilson']
const processes = ['svchost.exe', 'explorer.exe', 'chrome.exe', 'powershell.exe', 'cmd.exe', 'notepad.exe', 'winword.exe', 'outlook.exe']
const hosts = ['WS-042', 'WS-055', 'WS-071', 'WS-108', 'SRV-DC01', 'SRV-DB01', 'SRV-WEB01', 'SRV-APP01']
const levels = ['info', 'warning', 'error']
const protocols = ['tcp', 'udp', 'dns', 'http', 'https', 'smb']

export function generateMockResults(count = 100) {
  const results = []
  for (let i = 0; i < count; i++) {
    const ts = new Date(now - Math.random() * 24 * hr).toISOString()
    const action = actions[Math.floor(Math.random() * actions.length)]
    results.push({
      _id: `evt-${String(i + 1).padStart(5, '0')}`,
      _index: 'akeso-events-2026.03.16',
      '@timestamp': ts,
      'event.action': action,
      'event.category': action.includes('logon') ? 'authentication' : action.includes('process') ? 'process' : action.includes('file') ? 'file' : action.includes('network') || action.includes('dns') ? 'network' : 'host',
      'event.outcome': action === 'logon_failure' ? 'failure' : 'success',
      'source.ip': randomIp(),
      'destination.ip': randomIp(),
      'source.port': Math.floor(Math.random() * 60000) + 1024,
      'destination.port': [22, 80, 443, 445, 3389, 5985, 8080][Math.floor(Math.random() * 7)],
      'user.name': users[Math.floor(Math.random() * users.length)],
      'process.name': processes[Math.floor(Math.random() * processes.length)],
      'host.name': hosts[Math.floor(Math.random() * hosts.length)],
      'log.level': levels[Math.floor(Math.random() * levels.length)],
      'network.protocol': protocols[Math.floor(Math.random() * protocols.length)],
      message: `${action} event from ${hosts[Math.floor(Math.random() * hosts.length)]}`,
    })
  }
  return results.sort((a, b) => new Date(b['@timestamp']) - new Date(a['@timestamp']))
}

// Generate histogram buckets from results
export function generateHistogramBuckets(results, bucketCount = 30) {
  if (results.length === 0) return []

  const timestamps = results.map(r => new Date(r['@timestamp']).getTime())
  const minTs = Math.min(...timestamps)
  const maxTs = Math.max(...timestamps)
  const range = maxTs - minTs || 1
  const bucketSize = range / bucketCount

  const buckets = Array.from({ length: bucketCount }, (_, i) => ({
    time: new Date(minTs + i * bucketSize).toISOString(),
    count: 0,
  }))

  timestamps.forEach(ts => {
    const idx = Math.min(Math.floor((ts - minTs) / bucketSize), bucketCount - 1)
    buckets[idx].count++
  })

  return buckets
}

// Compute field statistics from results
export function computeFieldStats(results) {
  const stats = {}
  if (results.length === 0) return stats

  const fields = ['event.action', 'event.category', 'user.name', 'host.name', 'source.ip', 'destination.ip', 'process.name', 'log.level', 'network.protocol', 'destination.port']

  fields.forEach(field => {
    const counts = {}
    results.forEach(r => {
      const val = r[field]
      if (val != null) {
        const key = String(val)
        counts[key] = (counts[key] || 0) + 1
      }
    })
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10)
    if (sorted.length > 0) {
      stats[field] = {
        total: results.length,
        values: sorted.map(([value, count]) => ({ value, count, pct: Math.round((count / results.length) * 100) })),
      }
    }
  })

  return stats
}
