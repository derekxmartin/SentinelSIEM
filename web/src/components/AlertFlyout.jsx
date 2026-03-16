import { useState } from 'react'
import { XMarkIcon } from '@heroicons/react/24/outline'
import { Tab, TabGroup, TabList, TabPanel, TabPanels } from '@headlessui/react'
import SeverityBadge from './SeverityBadge'
import StatusBadge from './StatusBadge'

function formatTimestamp(ts) {
  const d = new Date(ts)
  const diff = Date.now() - d.getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return d.toLocaleDateString()
}

function OverviewTab({ alert }) {
  return (
    <div className="space-y-4">
      <div>
        <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Rule Description</h4>
        <p className="text-sm text-slate-700 dark:text-slate-300">{alert.ruleDescription}</p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">MITRE ATT&CK</h4>
          <p className="text-sm text-slate-700 dark:text-slate-300">{alert.mitreTactic}</p>
          <p className="text-xs text-slate-500 dark:text-slate-400">{alert.mitreTechniqueId}</p>
        </div>
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Severity</h4>
          <SeverityBadge severity={alert.severity} />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Source IP</h4>
          <p className="text-sm font-mono text-slate-700 dark:text-slate-300">{alert.sourceIp || '—'}</p>
        </div>
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Destination IP</h4>
          <p className="text-sm font-mono text-slate-700 dark:text-slate-300">{alert.destinationIp || '—'}</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">User</h4>
          <p className="text-sm text-slate-700 dark:text-slate-300">{alert.user || '—'}</p>
        </div>
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Assignee</h4>
          <p className="text-sm text-slate-700 dark:text-slate-300">{alert.assignee || 'Unassigned'}</p>
        </div>
      </div>
    </div>
  )
}

function EvidenceTab({ alert }) {
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">Event Fields</h4>
      <div className="rounded-lg border border-slate-200 dark:border-slate-700 divide-y divide-slate-200 dark:divide-slate-700">
        {alert.events.map((evt, i) => (
          <div key={i} className="flex items-center px-3 py-2 text-sm">
            <span className="text-slate-500 dark:text-slate-400 font-mono text-xs w-48 shrink-0 truncate" title={evt.field}>
              {evt.field}
            </span>
            <span className="text-slate-800 dark:text-slate-200 font-mono text-xs truncate" title={evt.value}>
              {evt.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

function TimelineTab({ alert }) {
  return (
    <div className="space-y-1">
      <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-3">Related Events</h4>
      <div className="relative pl-4 border-l-2 border-slate-200 dark:border-slate-700 space-y-4">
        {alert.relatedEvents.map((evt, i) => (
          <div key={i} className="relative">
            <div className="absolute -left-[21px] top-1.5 h-2.5 w-2.5 rounded-full bg-indigo-500 border-2 border-white dark:border-slate-900" />
            <div>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {formatTimestamp(evt.timestamp)}
                {evt.source && <span className="ml-2 text-slate-400 dark:text-slate-500">{evt.source}</span>}
                {evt.user && <span className="ml-2 text-slate-400 dark:text-slate-500">{evt.user}</span>}
              </p>
              <p className="text-sm text-slate-700 dark:text-slate-300 mt-0.5">
                <span className="font-medium">{evt.action}</span>
                {evt.detail && <span className="text-slate-500 dark:text-slate-400"> — {evt.detail}</span>}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function AlertFlyout({ alert, onClose, onAcknowledge, onEscalate, onCloseAlert }) {
  if (!alert) return null

  return (
    <div className="fixed inset-y-0 right-0 z-40 w-[480px] max-w-full flex flex-col bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-700 shadow-2xl">
      {/* Header */}
      <div className="flex items-start gap-3 p-4 border-b border-slate-200 dark:border-slate-700">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <SeverityBadge severity={alert.severity} />
            <StatusBadge status={alert.status} />
          </div>
          <h3 className="text-sm font-semibold text-slate-900 dark:text-white truncate">{alert.ruleName}</h3>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
            {formatTimestamp(alert.timestamp)} · {alert.id}
          </p>
        </div>
        <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-white p-1">
          <XMarkIcon className="h-5 w-5" />
        </button>
      </div>

      {/* Tabs */}
      <TabGroup className="flex-1 flex flex-col min-h-0">
        <TabList className="flex border-b border-slate-200 dark:border-slate-700 px-4">
          {['Overview', 'Evidence', 'Timeline'].map((tab) => (
            <Tab
              key={tab}
              className={({ selected }) =>
                `px-3 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors outline-none ${
                  selected
                    ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                    : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'
                }`
              }
            >
              {tab}
            </Tab>
          ))}
        </TabList>

        <TabPanels className="flex-1 overflow-y-auto p-4">
          <TabPanel><OverviewTab alert={alert} /></TabPanel>
          <TabPanel><EvidenceTab alert={alert} /></TabPanel>
          <TabPanel><TimelineTab alert={alert} /></TabPanel>
        </TabPanels>
      </TabGroup>

      {/* Footer actions */}
      <div className="flex items-center gap-2 p-4 border-t border-slate-200 dark:border-slate-700">
        {alert.status === 'new' && (
          <button
            onClick={() => onAcknowledge?.(alert.id)}
            className="flex-1 px-3 py-2 text-sm font-medium rounded-lg bg-indigo-600 text-white hover:bg-indigo-500 transition-colors"
          >
            Acknowledge
          </button>
        )}
        {alert.status !== 'escalated' && alert.status !== 'closed' && (
          <button
            onClick={() => onEscalate?.(alert.id)}
            className="flex-1 px-3 py-2 text-sm font-medium rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
          >
            Escalate to Case
          </button>
        )}
        {alert.status !== 'closed' && (
          <button
            onClick={() => onCloseAlert?.(alert.id)}
            className="px-3 py-2 text-sm font-medium rounded-lg text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            Close
          </button>
        )}
      </div>
    </div>
  )
}
