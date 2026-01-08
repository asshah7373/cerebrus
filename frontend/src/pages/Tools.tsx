import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Search,
  Shield,
  Globe,
  Network,
  Key,
  Terminal,
  AlertTriangle
} from 'lucide-react'
import { api } from '../utils/api'

const categoryIcons: Record<string, React.ElementType> = {
  recon: Search,
  scanning: Shield,
  enumeration: Search,
  exploitation: AlertTriangle,
  credential: Key,
  web: Globe,
  network: Network,
  utility: Terminal,
}

function ToolCard({ tool }: { tool: any }) {
  const [expanded, setExpanded] = useState(false)
  const Icon = categoryIcons[tool.category] || Terminal

  const riskColors: Record<string, string> = {
    low: 'bg-green-500/20 text-green-400',
    medium: 'bg-yellow-500/20 text-yellow-400',
    high: 'bg-orange-500/20 text-orange-400',
    critical: 'bg-red-500/20 text-red-400',
  }

  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
      <div
        className="p-6 cursor-pointer"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gray-700 rounded-lg">
              <Icon className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-white">{tool.name}</h3>
              <p className="text-sm text-gray-400">{tool.category}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className={`px-2 py-1 text-xs rounded ${riskColors[tool.risk_level] || riskColors.low}`}>
              {tool.risk_level}
            </span>
            {tool.requires_root && (
              <span className="px-2 py-1 text-xs bg-red-500/20 text-red-400 rounded">
                root
              </span>
            )}
          </div>
        </div>

        <p className="text-gray-400 text-sm">{tool.description}</p>

        {expanded && (
          <div className="mt-4 pt-4 border-t border-gray-700">
            <h4 className="text-sm font-medium text-white mb-2">Options</h4>
            <div className="bg-gray-900 rounded-lg p-4">
              <pre className="text-xs text-gray-400 overflow-x-auto">
                {JSON.stringify(tool.options_schema, null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default function Tools() {
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')

  const { data: tools, isLoading } = useQuery({
    queryKey: ['tools'],
    queryFn: () => api.get('/api/tools').then(r => r.data),
  })

  const { data: categories } = useQuery({
    queryKey: ['tool-categories'],
    queryFn: () => api.get('/api/tools/categories').then(r => r.data),
  })

  const filteredTools = tools?.tools?.filter((tool: any) => {
    if (selectedCategory && tool.category !== selectedCategory) return false
    if (searchQuery && !tool.name.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !tool.description.toLowerCase().includes(searchQuery.toLowerCase())) return false
    return true
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Tools</h1>
        <p className="text-gray-400 mt-1">
          Available pentesting tools and their configurations
        </p>
      </div>

      {/* Search and Filter */}
      <div className="flex flex-col sm:flex-row gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search tools..."
            className="w-full pl-10 pr-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-blue-500"
          />
        </div>
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={() => setSelectedCategory(null)}
            className={`px-3 py-2 rounded-lg text-sm transition-colors ${
              selectedCategory === null
                ? 'bg-blue-600 text-white'
                : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
            }`}
          >
            All
          </button>
          {categories?.categories?.map((cat: any) => (
            <button
              key={cat.id}
              onClick={() => setSelectedCategory(cat.id)}
              className={`px-3 py-2 rounded-lg text-sm transition-colors ${
                selectedCategory === cat.id
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
              }`}
            >
              {cat.name}
            </button>
          ))}
        </div>
      </div>

      {/* Tools Grid */}
      {isLoading ? (
        <div className="flex items-center justify-center py-12">
          <div className="spinner" />
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filteredTools?.map((tool: any) => (
            <ToolCard key={tool.name} tool={tool} />
          ))}
        </div>
      )}

      {filteredTools?.length === 0 && !isLoading && (
        <div className="text-center py-12 bg-gray-800 rounded-xl border border-gray-700">
          <Terminal className="w-12 h-12 mx-auto mb-3 text-gray-500" />
          <h3 className="text-lg font-medium text-white mb-1">No tools found</h3>
          <p className="text-gray-400">Try adjusting your search or filters</p>
        </div>
      )}
    </div>
  )
}
