// Mock dashboard data for development. Will be replaced by API calls.

const now = Date.now()
const hr = 60 * 60 * 1000
const day = 24 * hr

// 7-day sparkline data for KPI cards
function generateSparkline(base, variance, points = 7) {
  return Array.from({ length: points }, (_, i) => ({
    day: i,
    value: Math.max(0, base + (Math.random() - 0.5) * variance * 2),
  }))
}

export const kpiData = {
  eventsPerSec: {
    label: 'Events/sec',
    value: 2847,
    sparkline: generateSparkline(2800, 400),
    change: 12.3,
  },
  openAlerts: {
    label: 'Open Alerts',
    value: 23,
    sparkline: generateSparkline(20, 8),
    change: -8.1,
    severityDots: { critical: 2, high: 5, medium: 9, low: 7 },
  },
  mttd: {
    label: 'MTTD',
    value: '4.2m',
    sparkline: generateSparkline(4.5, 2),
    change: -15.0,
  },
  mttr: {
    label: 'MTTR',
    value: '38m',
    sparkline: generateSparkline(40, 15),
    change: -5.4,
  },
  sourceHealth: {
    label: 'Source Health',
    value: '12/14',
    sparkline: generateSparkline(12, 2),
    change: 0,
    gauge: { active: 12, expected: 14 },
  },
}

// 24-hour alert trend by severity (stacked area chart)
export const alertTrendData = Array.from({ length: 24 }, (_, i) => {
  const hour = new Date(now - (23 - i) * hr)
  return {
    time: hour.toISOString(),
    hour: hour.getHours().toString().padStart(2, '0') + ':00',
    critical: Math.floor(Math.random() * 3),
    high: Math.floor(Math.random() * 5) + 1,
    medium: Math.floor(Math.random() * 8) + 2,
    low: Math.floor(Math.random() * 6) + 1,
  }
})

// Top 10 triggered rules
export const topRulesData = [
  { rule: 'Brute Force Login Attempts', count: 47, severity: 'medium' },
  { rule: 'Suspicious PowerShell Execution', count: 34, severity: 'high' },
  { rule: 'NDR C2 Beacon Detected', count: 28, severity: 'critical' },
  { rule: 'New Service Installed', count: 24, severity: 'low' },
  { rule: 'Credential Dumping via LSASS', count: 19, severity: 'critical' },
  { rule: 'DLP Policy Violation', count: 16, severity: 'medium' },
  { rule: 'Malware Detection — Quarantine', count: 14, severity: 'high' },
  { rule: 'Suspicious SMB Lateral Movement', count: 11, severity: 'high' },
  { rule: 'DNS Tunneling Detected', count: 8, severity: 'medium' },
  { rule: 'Anomalous User Login Location', count: 6, severity: 'medium' },
].sort((a, b) => b.count - a.count)

// Source health summary
export const sourceHealthData = [
  { name: 'AkesoEDR', type: 'EDR', status: 'healthy', eps: 1240, lastEvent: new Date(now - 2000).toISOString() },
  { name: 'CrowdStrike AV', type: 'AV', status: 'healthy', eps: 680, lastEvent: new Date(now - 5000).toISOString() },
  { name: 'Symantec DLP', type: 'DLP', status: 'healthy', eps: 120, lastEvent: new Date(now - 8000).toISOString() },
  { name: 'Vectra NDR', type: 'NDR', status: 'healthy', eps: 340, lastEvent: new Date(now - 3000).toISOString() },
  { name: 'pfSense Firewall', type: 'Firewall', status: 'healthy', eps: 890, lastEvent: new Date(now - 1000).toISOString() },
  { name: 'Windows DC (Syslog)', type: 'Syslog', status: 'healthy', eps: 450, lastEvent: new Date(now - 4000).toISOString() },
  { name: 'Linux App Servers', type: 'Syslog', status: 'degraded', eps: 85, lastEvent: new Date(now - 45000).toISOString() },
  { name: 'AWS CloudTrail', type: 'Cloud', status: 'healthy', eps: 210, lastEvent: new Date(now - 6000).toISOString() },
  { name: 'Okta SSO', type: 'IAM', status: 'healthy', eps: 45, lastEvent: new Date(now - 12000).toISOString() },
  { name: 'Palo Alto NGFW', type: 'Firewall', status: 'healthy', eps: 760, lastEvent: new Date(now - 2000).toISOString() },
  { name: 'Exchange Server', type: 'Email', status: 'healthy', eps: 95, lastEvent: new Date(now - 15000).toISOString() },
  { name: 'Cisco Switch Stack', type: 'Network', status: 'healthy', eps: 320, lastEvent: new Date(now - 3000).toISOString() },
  { name: 'Dev Lab Syslog', type: 'Syslog', status: 'error', eps: 0, lastEvent: new Date(now - 2 * hr).toISOString() },
  { name: 'Legacy IDS', type: 'IDS', status: 'error', eps: 0, lastEvent: new Date(now - 6 * hr).toISOString() },
]

// NDR Host Risk — Critical and High quadrant hosts
export const ndrHostRiskData = [
  { ip: '10.1.2.45', hostname: 'WS-042', threatScore: 94, certaintyScore: 88, quadrant: 'critical', activeDetections: 4, topTactic: 'Command and Control', lastDetection: new Date(now - 12 * 60000).toISOString() },
  { ip: '10.1.6.15', hostname: 'WS-071', threatScore: 82, certaintyScore: 76, quadrant: 'critical', activeDetections: 2, topTactic: 'Execution', lastDetection: new Date(now - 3 * hr).toISOString() },
  { ip: '10.1.4.12', hostname: 'WS-108', threatScore: 68, certaintyScore: 72, quadrant: 'high', activeDetections: 1, topTactic: 'Execution', lastDetection: new Date(now - 45 * 60000).toISOString() },
  { ip: '10.1.5.33', hostname: 'WS-055', threatScore: 55, certaintyScore: 65, quadrant: 'high', activeDetections: 1, topTactic: 'Exfiltration', lastDetection: new Date(now - 1.5 * hr).toISOString() },
  { ip: '192.168.1.100', hostname: 'EXT-SCAN-01', threatScore: 52, certaintyScore: 60, quadrant: 'high', activeDetections: 1, topTactic: 'Credential Access', lastDetection: new Date(now - 2 * hr).toISOString() },
]

export const ndrSummary = {
  totalMonitored: 142,
  critical: 2,
  high: 3,
  medium: 8,
  low: 129,
}
