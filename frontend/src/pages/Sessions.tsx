import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Plus,
  Play,
  Pause,
  StopCircle,
  Trash2,
  ExternalLink,
  Clock,
  Target,
  AlertTriangle
} from 'lucide-react'
import { api } from '../utils/api'
import { formatDistanceToNow } from 'date-fns'

interface Session {
  id: string
  name: string
  objective: string
  status: string
  automation_level: string
  created_at: string
  target_count: number
  finding_count: number
}

function CreateSessionModal({
  isOpen,
  onClose
}: {
  isOpen: boolean
  onClose: () => void
}) {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [objective, setObjective] = useState('')
  const [targetAddress, setTargetAddress] = useState('')
  const [targetType, setTargetType] = useState('web')

  const createMutation = useMutation({
    mutationFn: (data: any) => api.post('/api/sessions', data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['sessions'] })
      onClose()
      setName('')
      setObjective('')
      setTargetAddress('')
    },
  })

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-xl w-full max-w-lg mx-4 border border-gray-700">
        <div className="px-6 py-4 border-b border-gray-700">
          <h2 className="text-xl font-semibold text-white">Create New Session</h2>
        </div>

        <form onSubmit={(e) => {
          e.preventDefault()
          createMutation.mutate({
            name,
            objective,
            targets: targetAddress ? [{
              name: targetAddress,
              address: targetAddress,
              type: targetType,
            }] : [],
          })
        }}>
          <div className="p-6 space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Session Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                placeholder="e.g., Web App Assessment"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Objective
              </label>
              <textarea
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                rows={3}
                placeholder="Describe the pentesting objective..."
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Initial Target (optional)
              </label>
              <div className="flex gap-2">
                <select
                  value={targetType}
                  onChange={(e) => setTargetType(e.target.value)}
                  className="px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="web">Web</option>
                  <option value="network">Network</option>
                  <option value="api">API</option>
                </select>
                <input
                  type="text"
                  value={targetAddress}
                  onChange={(e) => setTargetAddress(e.target.value)}
                  className="flex-1 px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  placeholder="URL or IP address"
                />
              </div>
            </div>
          </div>

          <div className="px-6 py-4 border-t border-gray-700 flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-gray-300 hover:text-white transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createMutation.isPending}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50"
            >
              {createMutation.isPending ? 'Creating...' : 'Create Session'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function SessionCard({ session }: { session: Session }) {
  const queryClient = useQueryClient()
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  const startMutation = useMutation({
    mutationFn: () => api.post(`/api/sessions/${session.id}/start`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sessions'] }),
  })

  const pauseMutation = useMutation({
    mutationFn: () => api.post(`/api/sessions/${session.id}/pause`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sessions'] }),
  })

  const stopMutation = useMutation({
    mutationFn: () => api.post(`/api/sessions/${session.id}/stop`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sessions'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: () => api.delete(`/api/sessions/${session.id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sessions'] }),
  })

  const statusColors: Record<string, string> = {
    created: 'bg-gray-500',
    running: 'bg-green-500',
    paused: 'bg-yellow-500',
    completed: 'bg-blue-500',
    failed: 'bg-red-500',
  }

  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
      <div className="p-6">
        <div className="flex items-start justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full ${statusColors[session.status] || 'bg-gray-500'}`} />
            <h3 className="text-lg font-semibold text-white">{session.name}</h3>
          </div>
          <span className="text-xs text-gray-400 bg-gray-700 px-2 py-1 rounded">
            {session.status}
          </span>
        </div>

        <p className="text-gray-400 text-sm mb-4 line-clamp-2">
          {session.objective}
        </p>

        <div className="flex items-center gap-4 text-sm text-gray-400 mb-4">
          <div className="flex items-center gap-1">
            <Target className="w-4 h-4" />
            <span>{session.target_count} targets</span>
          </div>
          <div className="flex items-center gap-1">
            <AlertTriangle className="w-4 h-4" />
            <span>{session.finding_count} findings</span>
          </div>
          <div className="flex items-center gap-1">
            <Clock className="w-4 h-4" />
            <span>{formatDistanceToNow(new Date(session.created_at), { addSuffix: true })}</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {session.status === 'created' || session.status === 'paused' ? (
            <button
              onClick={() => startMutation.mutate()}
              disabled={startMutation.isPending}
              className="flex items-center gap-1 px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white text-sm rounded-lg transition-colors"
            >
              <Play className="w-4 h-4" />
              Start
            </button>
          ) : session.status === 'running' ? (
            <>
              <button
                onClick={() => pauseMutation.mutate()}
                disabled={pauseMutation.isPending}
                className="flex items-center gap-1 px-3 py-1.5 bg-yellow-600 hover:bg-yellow-700 text-white text-sm rounded-lg transition-colors"
              >
                <Pause className="w-4 h-4" />
                Pause
              </button>
              <button
                onClick={() => stopMutation.mutate()}
                disabled={stopMutation.isPending}
                className="flex items-center gap-1 px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-sm rounded-lg transition-colors"
              >
                <StopCircle className="w-4 h-4" />
                Stop
              </button>
            </>
          ) : null}

          <Link
            to={`/sessions/${session.id}`}
            className="flex items-center gap-1 px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-lg transition-colors ml-auto"
          >
            <ExternalLink className="w-4 h-4" />
            View Details
          </Link>

          {session.status !== 'running' && (
            <button
              onClick={() => setShowDeleteConfirm(true)}
              className="flex items-center gap-1 px-3 py-1.5 bg-red-600/20 hover:bg-red-600 text-red-400 hover:text-white text-sm rounded-lg transition-colors"
              title="Delete session"
            >
              <Trash2 className="w-4 h-4" />
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
      </div>
    </div>
  )
}

export default function Sessions() {
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.get('/api/sessions').then(r => r.data),
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Sessions</h1>
          <p className="text-gray-400 mt-1">
            Manage your pentesting sessions
          </p>
        </div>
        <button
          onClick={() => setIsCreateModalOpen(true)}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
        >
          <Plus className="w-5 h-5" />
          New Session
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="spinner" />
        </div>
      ) : data?.sessions?.length > 0 ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {data.sessions.map((session: Session) => (
            <SessionCard key={session.id} session={session} />
          ))}
        </div>
      ) : (
        <div className="text-center py-12 bg-gray-800 rounded-xl border border-gray-700">
          <Target className="w-12 h-12 mx-auto mb-3 text-gray-500" />
          <h3 className="text-lg font-medium text-white mb-1">No sessions yet</h3>
          <p className="text-gray-400 mb-4">
            Create your first pentesting session to get started
          </p>
          <button
            onClick={() => setIsCreateModalOpen(true)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
          >
            Create Session
          </button>
        </div>
      )}

      <CreateSessionModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
      />
    </div>
  )
}
