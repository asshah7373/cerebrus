import { useQuery } from '@tanstack/react-query'
import {
  Target,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Activity,
  Shield,
  Zap
} from 'lucide-react'
import { api } from '../utils/api'

function StatCard({
  title,
  value,
  icon: Icon,
  color
}: {
  title: string
  value: string | number
  icon: React.ElementType
  color: string
}) {
  return (
    <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-gray-400 text-sm">{title}</p>
          <p className="text-3xl font-bold text-white mt-1">{value}</p>
        </div>
        <div className={`p-3 rounded-lg ${color}`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
    </div>
  )
}

function SeverityBar({
  label,
  count,
  total,
  color
}: {
  label: string
  count: number
  total: number
  color: string
}) {
  const percentage = total > 0 ? (count / total) * 100 : 0

  return (
    <div className="space-y-1">
      <div className="flex justify-between text-sm">
        <span className="text-gray-400">{label}</span>
        <span className="text-white font-medium">{count}</span>
      </div>
      <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
        <div
          className={`h-full ${color} transition-all duration-500`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  )
}

export default function Dashboard() {
  const { data: sessions } = useQuery({
    queryKey: ['sessions'],
    queryFn: () => api.get('/api/sessions').then(r => r.data),
  })

  const activeSessions = sessions?.sessions?.filter(
    (s: any) => s.status === 'running'
  ).length || 0

  const totalFindings = sessions?.sessions?.reduce(
    (acc: number, s: any) => acc + (s.finding_count || 0),
    0
  ) || 0

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <p className="text-gray-400 mt-1">
          Overview of your pentesting activities
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Active Sessions"
          value={activeSessions}
          icon={Activity}
          color="bg-blue-600"
        />
        <StatCard
          title="Total Findings"
          value={totalFindings}
          icon={AlertTriangle}
          color="bg-orange-600"
        />
        <StatCard
          title="Targets Scanned"
          value={sessions?.sessions?.reduce((acc: number, s: any) => acc + (s.target_count || 0), 0) || 0}
          icon={Target}
          color="bg-purple-600"
        />
        <StatCard
          title="Completed Sessions"
          value={sessions?.sessions?.filter((s: any) => s.status === 'completed').length || 0}
          icon={CheckCircle2}
          color="bg-green-600"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Sessions */}
        <div className="lg:col-span-2 bg-gray-800 rounded-xl border border-gray-700">
          <div className="px-6 py-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">Recent Sessions</h2>
          </div>
          <div className="p-6">
            {sessions?.sessions?.length > 0 ? (
              <div className="space-y-4">
                {sessions.sessions.slice(0, 5).map((session: any) => (
                  <div
                    key={session.id}
                    className="flex items-center justify-between p-4 bg-gray-700/50 rounded-lg"
                  >
                    <div className="flex items-center gap-4">
                      <div className={`w-2 h-2 rounded-full ${
                        session.status === 'running' ? 'bg-green-500' :
                        session.status === 'completed' ? 'bg-blue-500' :
                        'bg-gray-500'
                      }`} />
                      <div>
                        <p className="text-white font-medium">{session.name}</p>
                        <p className="text-gray-400 text-sm">{session.objective?.slice(0, 50)}...</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-sm text-gray-400">{session.finding_count || 0} findings</p>
                      <p className="text-xs text-gray-500">{session.status}</p>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8 text-gray-400">
                <Shield className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No sessions yet</p>
                <p className="text-sm">Create a new session to get started</p>
              </div>
            )}
          </div>
        </div>

        {/* Findings by Severity */}
        <div className="bg-gray-800 rounded-xl border border-gray-700">
          <div className="px-6 py-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">Findings by Severity</h2>
          </div>
          <div className="p-6 space-y-4">
            <SeverityBar label="Critical" count={0} total={totalFindings} color="bg-red-600" />
            <SeverityBar label="High" count={0} total={totalFindings} color="bg-orange-500" />
            <SeverityBar label="Medium" count={0} total={totalFindings} color="bg-yellow-500" />
            <SeverityBar label="Low" count={0} total={totalFindings} color="bg-green-500" />
            <SeverityBar label="Info" count={0} total={totalFindings} color="bg-blue-500" />
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Quick Actions</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button className="flex items-center gap-3 p-4 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
            <Zap className="w-5 h-5" />
            <span className="font-medium">New Session</span>
          </button>
          <button className="flex items-center gap-3 p-4 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
            <Target className="w-5 h-5" />
            <span className="font-medium">Add Target</span>
          </button>
          <button className="flex items-center gap-3 p-4 bg-gray-700 hover:bg-gray-600 rounded-lg transition-colors">
            <Clock className="w-5 h-5" />
            <span className="font-medium">View History</span>
          </button>
        </div>
      </div>
    </div>
  )
}
