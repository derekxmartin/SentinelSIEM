import { useState, useEffect, useCallback } from 'react'
import { XMarkIcon, CheckCircleIcon, ClipboardDocumentIcon } from '@heroicons/react/24/outline'
import { sourceTypeOptions, parsersByType } from '../data/mockSources'

const steps = ['Select Type', 'Configure', 'Snippet', 'Verify']

function StepIndicator({ current }) {
  return (
    <div className="flex items-center gap-2 px-6 py-3 border-b border-slate-200 dark:border-slate-700">
      {steps.map((label, i) => (
        <div key={label} className="flex items-center gap-2">
          <div className={`flex items-center justify-center h-6 w-6 rounded-full text-xs font-medium ${
            i < current ? 'bg-green-500 text-white'
              : i === current ? 'bg-indigo-600 text-white'
              : 'bg-slate-200 dark:bg-slate-700 text-slate-500 dark:text-slate-400'
          }`}>
            {i < current ? '✓' : i + 1}
          </div>
          <span className={`text-xs font-medium ${
            i <= current ? 'text-slate-700 dark:text-slate-300' : 'text-slate-400 dark:text-slate-500'
          }`}>{label}</span>
          {i < steps.length - 1 && <div className="w-6 h-px bg-slate-300 dark:bg-slate-600" />}
        </div>
      ))}
    </div>
  )
}

// Step 1 — Type Selection
function TypeStep({ selected, onSelect }) {
  return (
    <div className="p-6">
      <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">Select the type of log source to onboard:</p>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        {sourceTypeOptions.map(opt => (
          <button
            key={opt.type}
            onClick={() => onSelect(opt)}
            className={`text-left p-3 rounded-lg border transition-colors ${
              selected?.type === opt.type
                ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-500/10 ring-1 ring-indigo-500'
                : 'border-slate-200 dark:border-slate-700 hover:border-indigo-300 dark:hover:border-indigo-600 bg-white dark:bg-slate-800'
            }`}
          >
            <div className="text-xl mb-1">{opt.icon}</div>
            <p className="text-sm font-medium text-slate-700 dark:text-slate-300">{opt.label}</p>
            <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">{opt.description}</p>
          </button>
        ))}
      </div>
    </div>
  )
}

// Step 2 — Configuration Form
function ConfigStep({ typeInfo, config, onChange }) {
  const parsers = parsersByType[typeInfo.type] || []
  const protocols = typeInfo.protocols || []

  const update = (field, value) => onChange({ ...config, [field]: value })

  return (
    <div className="p-6 space-y-4">
      <div>
        <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">Source Name *</label>
        <input
          type="text"
          value={config.name || ''}
          onChange={e => update('name', e.target.value)}
          placeholder={`e.g., Production ${typeInfo.label}`}
          className="w-full px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">Protocol *</label>
          <select
            value={config.protocol || protocols[0] || ''}
            onChange={e => update('protocol', e.target.value)}
            className="w-full px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            {protocols.map(p => <option key={p} value={p}>{p.replace(/_/g, ' ')}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">Parser *</label>
          <select
            value={config.parser || parsers[0] || ''}
            onChange={e => update('parser', e.target.value)}
            className="w-full px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            {parsers.map(p => <option key={p} value={p}>{p}</option>)}
          </select>
        </div>
      </div>

      {config.protocol?.startsWith('syslog') && (
        <div>
          <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">Syslog Port</label>
          <input
            type="number"
            value={config.port || 1514}
            onChange={e => update('port', parseInt(e.target.value) || 1514)}
            className="w-full px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
        </div>
      )}

      <div>
        <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">Expected Hosts (comma-separated)</label>
        <input
          type="text"
          value={config.expectedHosts || ''}
          onChange={e => update('expectedHosts', e.target.value)}
          placeholder="10.1.1.1, 10.1.1.2"
          className="w-full px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
      </div>

      <div>
        <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">Description</label>
        <textarea
          value={config.description || ''}
          onChange={e => update('description', e.target.value)}
          rows={2}
          className="w-full px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-none"
        />
      </div>
    </div>
  )
}

// Step 3 — Snippet Display
function SnippetStep({ config, apiKey }) {
  const [format, setFormat] = useState('toml')
  const [copied, setCopied] = useState(false)

  const snippet = generateMockSnippet(config, format, apiKey)

  const handleCopy = () => {
    navigator.clipboard?.writeText(snippet)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="p-6 space-y-4">
      <div>
        <p className="text-sm text-slate-600 dark:text-slate-400 mb-2">
          Source <span className="font-medium text-slate-700 dark:text-slate-300">{config.name}</span> created successfully.
          Use the snippet below to configure your source.
        </p>
        {apiKey && (
          <div className="flex items-center gap-2 p-2 rounded bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30">
            <span className="text-xs text-amber-700 dark:text-amber-400">API Key (save this — shown only once):</span>
            <code className="text-xs font-mono text-amber-800 dark:text-amber-300 select-all">{apiKey}</code>
          </div>
        )}
      </div>

      <div className="flex items-center justify-between">
        <div className="flex gap-1">
          {['toml', 'yaml', 'rsyslog', 'pfsense'].map(f => (
            <button
              key={f}
              onClick={() => setFormat(f)}
              className={`px-2.5 py-1 text-xs font-medium rounded transition-colors ${
                format === f
                  ? 'bg-indigo-600 text-white'
                  : 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-200 dark:hover:bg-slate-600'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 px-2 py-1 text-xs text-slate-500 dark:text-slate-400 hover:text-indigo-500 transition-colors"
        >
          <ClipboardDocumentIcon className="h-4 w-4" />
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>

      <pre className="p-4 rounded-lg bg-slate-900 text-green-400 text-xs font-mono overflow-auto max-h-60 whitespace-pre-wrap">
        {snippet}
      </pre>
    </div>
  )
}

// Step 4 — Verification
function VerifyStep({ config, verificationStatus }) {
  return (
    <div className="p-6 space-y-4">
      <p className="text-sm text-slate-600 dark:text-slate-400">
        Configure your source using the snippet from the previous step, then verify connectivity:
      </p>

      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 p-4 space-y-3">
        <div className="flex items-center gap-3">
          {verificationStatus === 'waiting' && (
            <>
              <div className="h-5 w-5 rounded-full border-2 border-indigo-500 border-t-transparent animate-spin" />
              <span className="text-sm text-slate-600 dark:text-slate-400">Waiting for first event from <span className="font-medium text-slate-700 dark:text-slate-300">{config.name}</span>...</span>
            </>
          )}
          {verificationStatus === 'success' && (
            <>
              <CheckCircleIcon className="h-5 w-5 text-green-500" />
              <span className="text-sm text-green-600 dark:text-green-400 font-medium">Events received! Source is active.</span>
            </>
          )}
          {verificationStatus === 'idle' && (
            <span className="text-sm text-slate-500 dark:text-slate-400">Click "Start Verification" to begin polling.</span>
          )}
        </div>
      </div>
    </div>
  )
}

function generateMockSnippet(config, format, apiKey) {
  const name = config.name || 'MySource'
  const parser = config.parser || 'generic'
  const key = apiKey || '<YOUR_API_KEY>'
  const port = config.port || 1514
  const isSyslog = config.protocol?.startsWith('syslog')

  if (format === 'toml') {
    if (isSyslog) {
      return `# AkesoSIEM source config for ${name}\n[syslog_output]\n  protocol = "${config.protocol?.replace('syslog_', '')}"\n  target = "<AKESO_HOST>:${port}"\n  source_type = "${parser}"`
    }
    return `# AkesoSIEM source config for ${name}\n[http_output]\n  endpoint = "https://<AKESO_HOST>:8080/api/v1/ingest"\n  source_type = "${parser}"\n  api_key = "${key}"\n  batch_size = 100\n  flush_interval = "5s"`
  }
  if (format === 'yaml') {
    if (isSyslog) {
      return `# AkesoSIEM source config for ${name}\nsyslog_output:\n  protocol: "${config.protocol?.replace('syslog_', '')}"\n  target: "<AKESO_HOST>:${port}"\n  source_type: "${parser}"`
    }
    return `# AkesoSIEM source config for ${name}\nhttp_output:\n  endpoint: "https://<AKESO_HOST>:8080/api/v1/ingest"\n  source_type: "${parser}"\n  api_key: "${key}"\n  batch_size: 100\n  flush_interval: "5s"`
  }
  if (format === 'rsyslog') {
    return `# rsyslog config for ${name}\n# Add to /etc/rsyslog.d/akeso.conf\n\n*.* @@<AKESO_HOST>:${port}`
  }
  // pfsense
  return `# pfSense config for ${name}\n# Navigate to: Status > System Logs > Settings\n#\n# 1. Check "Enable Remote Logging"\n# 2. Remote log servers: <AKESO_HOST>:${port}\n# 3. Remote Syslog Contents: Everything\n# 4. Click Save`
}

export default function SourceWizard({ onClose }) {
  const [step, setStep] = useState(0)
  const [typeInfo, setTypeInfo] = useState(null)
  const [config, setConfig] = useState({})
  const [apiKey] = useState(() => 'sk_' + Array.from({ length: 16 }, () => Math.floor(Math.random() * 16).toString(16)).join(''))
  const [verificationStatus, setVerificationStatus] = useState('idle')
  const [polling, setPolling] = useState(false)

  // Initialize config defaults when type is selected
  const handleTypeSelect = useCallback((opt) => {
    setTypeInfo(opt)
    setConfig(prev => ({
      ...prev,
      type: opt.type,
      protocol: opt.protocols[0],
      parser: (parsersByType[opt.type] || [])[0] || '',
    }))
  }, [])

  const isDirty = step > 0 || typeInfo !== null

  const handleBackdropClick = () => {
    if (!isDirty) onClose()
  }

  const canProceed = () => {
    if (step === 0) return typeInfo !== null
    if (step === 1) return config.name?.trim()
    return true
  }

  const handleNext = () => {
    if (step < steps.length - 1) setStep(step + 1)
    else onClose()
  }

  // Simulate verification polling
  useEffect(() => {
    if (!polling) return
    setVerificationStatus('waiting')
    const timer = setTimeout(() => {
      setVerificationStatus('success')
      setPolling(false)
    }, 3000)
    return () => clearTimeout(timer)
  }, [polling])

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={handleBackdropClick} />
      <div className="relative w-full max-w-2xl mx-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-2xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-slate-800 dark:text-white">Add Source</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>

        {/* Step indicator */}
        <StepIndicator current={step} />

        {/* Step content */}
        <div className="flex-1 overflow-y-auto">
          {step === 0 && <TypeStep selected={typeInfo} onSelect={handleTypeSelect} />}
          {step === 1 && <ConfigStep typeInfo={typeInfo} config={config} onChange={setConfig} />}
          {step === 2 && <SnippetStep config={config} apiKey={apiKey} />}
          {step === 3 && <VerifyStep config={config} verificationStatus={verificationStatus} />}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-slate-200 dark:border-slate-700">
          <div>
            {step > 0 && step < 3 && (
              <button
                onClick={() => setStep(step - 1)}
                className="px-4 py-2 text-sm font-medium text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200"
              >
                Back
              </button>
            )}
          </div>
          <div className="flex items-center gap-2">
            {step === 3 && verificationStatus !== 'success' && (
              <button
                onClick={() => setPolling(true)}
                disabled={polling}
                className="px-4 py-2 text-sm font-medium rounded-lg border border-indigo-500 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-500/10 disabled:opacity-50 transition-colors"
              >
                {polling ? 'Polling...' : 'Start Verification'}
              </button>
            )}
            {step === 3 && verificationStatus !== 'success' && (
              <button
                onClick={onClose}
                className="px-4 py-2 text-sm font-medium text-slate-500 dark:text-slate-400 hover:text-slate-700"
              >
                Skip
              </button>
            )}
            <button
              onClick={handleNext}
              disabled={!canProceed()}
              className="px-4 py-2 text-sm font-medium rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {step === steps.length - 1 ? 'Done' : step === 1 ? 'Create Source' : 'Next'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
