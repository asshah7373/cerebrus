import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Play,
  Pause,
  StopCircle,
  Target,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  Terminal,
  Shield,
  Trash2
} from 'lucide-react'
import { api } from '../utils/api'
import { useWebSocket } from '../hooks/useWebSocket'

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-600',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-green-500',
    info: 'bg-blue-500',
  }

  return (
    <span className={`px-2 py-0.5 text-xs font-medium text-white rounded ${colors[severity] || 'bg-gray-500'}`}>
      {severity.toUpperCase()}
    </span>
  )
}

function TaskCard({ task, onApprove }: { task: any; onApprove: (taskId: string, approved: boolean) => void }) {
  const statusIcons: Record<string, React.ElementType> = {
    pending: Clock,
    in_progress: Play,
    waiting_approval: AlertTriangle,
    approved: CheckCircle,
    rejected: XCircle,
    completed: CheckCircle,
    failed: XCircle,
  }

  const StatusIcon = statusIcons[task.status] || Clock

  return (
    <div className="bg-gray-700/50 rounded-lg p-4">
      <div className="flex items-start justify-between mb-2">
        <div className="flex items-center gap-2">
          <StatusIcon className={`w-4 h-4 ${
            task.status === 'completed' ? 'text-green-500' :
            task.status === 'failed' ? 'text-red-500' :
            task.status === 'waiting_approval' ? 'text-yellow-500' :
            'text-gray-400'
          }`} />
          <span className="text-white font-medium">{task.name}</span>
        </div>
        <span className="text-xs text-gray-400 bg-gray-600 px-2 py-0.5 rounded">
          {task.task_type}
        </span>
      </div>

      <div className="flex items-center gap-2 text-sm text-gray-400 mb-2">
        {task.tool && <span className="bg-gray-600 px-2 py-0.5 rounded">{task.tool}</span>}
        <span className={`px-2 py-0.5 rounded ${
          task.risk_level === 'high' ? 'bg-orange-500/20 text-orange-400' :
          task.risk_level === 'critical' ? 'bg-red-500/20 text-red-400' :
          'bg-gray-600'
        }`}>
          {task.risk_level}
        </span>
      </div>

      {task.status === 'waiting_approval' && (
        <div className="flex gap-2 mt-3">
          <button
            onClick={() => onApprove(task.id, true)}
            className="flex-1 px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white text-sm rounded transition-colors"
          >
            Approve
          </button>
          <button
            onClick={() => onApprove(task.id, false)}
            className="flex-1 px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-sm rounded transition-colors"
          >
            Reject
          </button>
        </div>
      )}
    </div>
  )
}

function FindingCard({ finding }: { finding: any }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="bg-gray-700/50 rounded-lg p-4">
      <div
        className="flex items-start justify-between cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div>
          <div className="flex items-center gap-2 mb-1">
            <SeverityBadge severity={finding.severity} />
            <span className="text-xs text-gray-400">{finding.category}</span>
          </div>
          <h4 className="text-white font-medium">{finding.title}</h4>
        </div>
        <span className="text-gray-400 text-sm">
          {expanded ? '−' : '+'}
        </span>
      </div>

      {expanded && (
        <div className="mt-4 space-y-3 text-sm">
          <div>
            <p className="text-gray-400 mb-1">Description:</p>
            <p className="text-gray-300">{finding.description}</p>
          </div>
          {finding.evidence && (
            <div>
              <p className="text-gray-400 mb-1">Evidence:</p>
              <pre className="bg-gray-800 p-2 rounded text-gray-300 text-xs overflow-x-auto">
                {finding.evidence}
              </pre>
            </div>
          )}
          {finding.remediation && (
            <div>
              <p className="text-gray-400 mb-1">Remediation:</p>
              <p className="text-gray-300">{finding.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function SessionDetail() {
  const { sessionId } = useParams<{ sessionId: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'overview' | 'tasks' | 'findings' | 'logs'>('overview')
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  // WebSocket connection for real-time updates
  const { messages, isConnected } = useWebSocket(sessionId || '')

  const { data: session } = useQuery({
    queryKey: ['session', sessionId],
    queryFn: () => api.get(`/api/sessions/${sessionId}`).then(r => r.data),
  })

  const { data: tasks } = useQuery({
    queryKey: ['tasks', sessionId],
    queryFn: () => api.get(`/api/tasks/session/${sessionId}`).then(r => r.data),
  })

  const { data: findings } = useQuery({
    queryKey: ['findings', sessionId],
    queryFn: () => api.get(`/api/findings/session/${sessionId}`).then(r => r.data),
  })

  const approveMutation = useMutation({
    mutationFn: ({ taskId, approved }: { taskId: string; approved: boolean }) =>
      api.post(`/api/tasks/${taskId}/approve`, { approved }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tasks', sessionId] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/api/sessions/${sessionId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
      navigate('/sessions')
    },
  })

  // Handle WebSocket messages
  useEffect(() => {
    const lastMessage = messages[messages.length - 1]
    if (lastMessage) {
      if (lastMessage.type === 'finding') {
        queryClient.invalidateQueries({ queryKey: ['findings', sessionId] })
      } else if (lastMessage.type === 'progress') {
        queryClient.invalidateQueries({ queryKey: ['tasks', sessionId] })
      }
    }
  }, [messages, queryClient, sessionId])

  if (!session) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="spinner" />
      </div>
    )
  }

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'tasks', label: 'Tasks', count: tasks?.total },
    { id: 'findings', label: 'Findings', count: findings?.total },
    { id: 'logs', label: 'Logs' },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <h1 className="text-2xl font-bold text-white">{session.name}</h1>
            <span className={`px-2 py-1 text-xs rounded ${
              session.status === 'running' ? 'bg-green-600' :
              session.status === 'completed' ? 'bg-blue-600' :
              'bg-gray-600'
            }`}>
              {session.status}
            </span>
            {isConnected && (
              <span className="flex items-center gap-1 text-xs text-green-400">
                <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                Live
              </span>
            )}
          </div>
          <p className="text-gray-400">{session.objective}</p>
        </div>

        {/* Delete button */}
        {session.status !== 'running' && (
          <button
            onClick={() => setShowDeleteConfirm(true)}
            className="flex items-center gap-2 px-4 py-2 bg-red-600/20 hover:bg-red-600 text-red-400 hover:text-white rounded-lg transition-colors"
          >
            <Trash2 className="w-4 h-4" />
            Delete
          </button>
        )}
      </div>

      {/* Delete confirmation modal */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" onClick={() => setShowDeleteConfirm(false)}>
          <div className="bg-gray-800 rounded-xl p-6 max-w-sm mx-4 border border-gray-700" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-semibold text-white mb-2">Delete Session?</h3>
            <p className="text-gray-400 text-sm mb-4">
              Are you sure you want to delete "{session.name}"? This will remove all associated targets, tasks, and findings.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowDeleteConfirm(false)}
                className="flex-1 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  deleteMutation.mutate()
                  setShowDeleteConfirm(false)
                }}
                disabled={deleteMutation.isPending}
                className="flex-1 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors disabled:opacity-50"
              >
                {deleteMutation.isPending ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-gray-700">
        <nav className="flex gap-4">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`py-3 px-1 border-b-2 transition-colors ${
                activeTab === tab.id
                  ? 'border-blue-500 text-white'
                  : 'border-transparent text-gray-400 hover:text-white'
              }`}
            >
              {tab.label}
              {tab.count !== undefined && (
                <span className="ml-2 text-xs bg-gray-700 px-2 py-0.5 rounded">
                  {tab.count}
                </span>
              )}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Stats */}
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Session Stats</h3>
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="flex items-center gap-2 text-gray-400 mb-1">
                  <Target className="w-4 h-4" />
                  <span className="text-sm">Targets</span>
                </div>
                <p className="text-2xl font-bold text-white">{session.target_count}</p>
              </div>
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="flex items-center gap-2 text-gray-400 mb-1">
                  <AlertTriangle className="w-4 h-4" />
                  <span className="text-sm">Findings</span>
                </div>
                <p className="text-2xl font-bold text-white">{session.finding_count}</p>
              </div>
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="flex items-center gap-2 text-gray-400 mb-1">
                  <CheckCircle className="w-4 h-4" />
                  <span className="text-sm">Completed Tasks</span>
                </div>
                <p className="text-2xl font-bold text-white">
                  {tasks?.tasks?.filter((t: any) => t.status === 'completed').length || 0}
                </p>
              </div>
              <div className="bg-gray-700/50 rounded-lg p-4">
                <div className="flex items-center gap-2 text-gray-400 mb-1">
                  <Clock className="w-4 h-4" />
                  <span className="text-sm">Pending</span>
                </div>
                <p className="text-2xl font-bold text-white">
                  {tasks?.tasks?.filter((t: any) => t.status === 'pending' || t.status === 'waiting_approval').length || 0}
                </p>
              </div>
            </div>
          </div>

          {/* Pending Approvals */}
          <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Pending Approvals</h3>
            <div className="space-y-3">
              {tasks?.tasks?.filter((t: any) => t.status === 'waiting_approval').map((task: any) => (
                <TaskCard
                  key={task.id}
                  task={task}
                  onApprove={(taskId, approved) => approveMutation.mutate({ taskId, approved })}
                />
              ))}
              {!tasks?.tasks?.some((t: any) => t.status === 'waiting_approval') && (
                <p className="text-gray-400 text-center py-4">No pending approvals</p>
              )}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'tasks' && (
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
          <div className="space-y-3">
            {tasks?.tasks?.map((task: any) => (
              <TaskCard
                key={task.id}
                task={task}
                onApprove={(taskId, approved) => approveMutation.mutate({ taskId, approved })}
              />
            ))}
            {!tasks?.tasks?.length && (
              <p className="text-gray-400 text-center py-8">No tasks yet</p>
            )}
          </div>
        </div>
      )}

      {activeTab === 'findings' && (
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
          <div className="space-y-3">
            {findings?.findings?.map((finding: any) => (
              <FindingCard key={finding.id} finding={finding} />
            ))}
            {!findings?.findings?.length && (
              <div className="text-center py-8">
                <Shield className="w-12 h-12 mx-auto mb-3 text-gray-500" />
                <p className="text-gray-400">No findings yet</p>
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'logs' && (
        <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
          <div className="terminal-output bg-gray-900 rounded-lg p-4 h-96 overflow-auto">
            {messages.map((msg, i) => (
              <div key={i} className="text-gray-300 text-sm mb-1">
                <span className="text-gray-500">[{msg.type}]</span> {JSON.stringify(msg)}
              </div>
            ))}
            {messages.length === 0 && (
              <p className="text-gray-500">Waiting for activity...</p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
