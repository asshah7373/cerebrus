import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import {
  Save,
  RefreshCw,
  Shield,
  Zap,
  Database,
  Terminal
} from 'lucide-react'
import { api } from '../utils/api'

function SettingCard({
  title,
  description,
  icon: Icon,
  children
}: {
  title: string
  description: string
  icon: React.ElementType
  children: React.ReactNode
}) {
  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
      <div className="flex items-start gap-4 mb-4">
        <div className="p-2 bg-gray-700 rounded-lg">
          <Icon className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          <p className="text-sm text-gray-400">{description}</p>
        </div>
      </div>
      <div className="pl-12">
        {children}
      </div>
    </div>
  )
}

export default function Settings() {
  const queryClient = useQueryClient()
  const [localSettings, setLocalSettings] = useState<Record<string, any>>({})

  const { data: settings, isLoading } = useQuery({
    queryKey: ['settings'],
    queryFn: () => api.get('/api/settings').then(r => r.data),
    onSuccess: (data) => {
      const initial: Record<string, any> = {}
      Object.entries(data.settings).forEach(([key, value]: [string, any]) => {
        initial[key] = value.value
      })
      setLocalSettings(initial)
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ key, value }: { key: string; value: any }) =>
      api.put(`/api/settings/${key}`, { value }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] })
    },
  })

  const resetMutation = useMutation({
    mutationFn: () => api.post('/api/settings/reset'),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] })
    },
  })

  const handleSave = (key: string) => {
    updateMutation.mutate({ key, value: localSettings[key] })
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="spinner" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Settings</h1>
          <p className="text-gray-400 mt-1">
            Configure Cerebrus behavior and preferences
          </p>
        </div>
        <button
          onClick={() => resetMutation.mutate()}
          disabled={resetMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Reset to Defaults
        </button>
      </div>

      <div className="space-y-6">
        {/* Automation Settings */}
        <SettingCard
          title="Automation"
          description="Control how much automation is allowed"
          icon={Zap}
        >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Automation Level
              </label>
              <select
                value={localSettings.automation_level || 'semi_auto'}
                onChange={(e) => setLocalSettings({ ...localSettings, automation_level: e.target.value })}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
              >
                <option value="manual">Manual - All operations require approval</option>
                <option value="semi_auto">Semi-Auto - Low-risk operations auto-execute</option>
                <option value="full_auto">Full Auto - All operations auto-execute</option>
              </select>
              <button
                onClick={() => handleSave('automation_level')}
                className="mt-2 px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors"
              >
                Save
              </button>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Maximum Auto-Approve Risk Level
              </label>
              <select
                value={localSettings.max_risk_auto || 'low'}
                onChange={(e) => setLocalSettings({ ...localSettings, max_risk_auto: e.target.value })}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical (Not Recommended)</option>
              </select>
              <button
                onClick={() => handleSave('max_risk_auto')}
                className="mt-2 px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors"
              >
                Save
              </button>
            </div>
          </div>
        </SettingCard>

        {/* Security Settings */}
        <SettingCard
          title="Security"
          description="Authorization and safety controls"
          icon={Shield}
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-white font-medium">Require Target Authorization</p>
                <p className="text-sm text-gray-400">Targets must be explicitly authorized before testing</p>
              </div>
              <button
                onClick={() => {
                  const newValue = !localSettings.require_authorization
                  setLocalSettings({ ...localSettings, require_authorization: newValue })
                  updateMutation.mutate({ key: 'require_authorization', value: newValue })
                }}
                className={`relative w-12 h-6 rounded-full transition-colors ${
                  localSettings.require_authorization !== false ? 'bg-blue-600' : 'bg-gray-600'
                }`}
              >
                <span
                  className={`absolute top-1 left-1 w-4 h-4 bg-white rounded-full transition-transform ${
                    localSettings.require_authorization !== false ? 'translate-x-6' : ''
                  }`}
                />
              </button>
            </div>
          </div>
        </SettingCard>

        {/* Performance Settings */}
        <SettingCard
          title="Performance"
          description="Rate limiting and resource management"
          icon={Database}
        >
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Max Concurrent Scans
              </label>
              <input
                type="number"
                value={localSettings.max_concurrent_scans || 5}
                onChange={(e) => setLocalSettings({ ...localSettings, max_concurrent_scans: parseInt(e.target.value) })}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                min={1}
                max={20}
              />
              <button
                onClick={() => handleSave('max_concurrent_scans')}
                className="mt-2 px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors"
              >
                Save
              </button>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Request Delay (ms)
              </label>
              <input
                type="number"
                value={localSettings.request_delay_ms || 100}
                onChange={(e) => setLocalSettings({ ...localSettings, request_delay_ms: parseInt(e.target.value) })}
                className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                min={0}
                max={5000}
                step={50}
              />
              <button
                onClick={() => handleSave('request_delay_ms')}
                className="mt-2 px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors"
              >
                Save
              </button>
            </div>
          </div>
        </SettingCard>

        {/* Logging Settings */}
        <SettingCard
          title="Logging"
          description="Configure logging verbosity"
          icon={Terminal}
        >
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Log Level
            </label>
            <select
              value={localSettings.log_level || 'INFO'}
              onChange={(e) => setLocalSettings({ ...localSettings, log_level: e.target.value })}
              className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
            >
              <option value="DEBUG">Debug - All messages</option>
              <option value="INFO">Info - Standard logging</option>
              <option value="WARNING">Warning - Warnings and errors</option>
              <option value="ERROR">Error - Errors only</option>
            </select>
            <button
              onClick={() => handleSave('log_level')}
              className="mt-2 px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded transition-colors"
            >
              Save
            </button>
          </div>
        </SettingCard>
      </div>
    </div>
  )
}
