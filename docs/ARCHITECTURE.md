# Cerebrus Architecture Documentation

## Overview

Cerebrus is built on a modular, event-driven architecture that separates concerns between AI reasoning, tool execution, and user interface components.

## Core Components

### 1. LangGraph Orchestrator

The orchestrator (`backend/core/orchestrator.py`) manages the pentesting workflow using LangGraph's state machine capabilities.

**Key Features:**
- State-based workflow management
- Conditional routing between agents
- Human-in-the-loop interruption points
- Checkpoint support for session resumption

**Workflow Phases:**
1. **Initialization** - Session setup and target validation
2. **Authorization Check** - Verify target permissions
3. **Planning** - Generate attack strategy
4. **Agent Selection** - Route to appropriate agent
5. **Reasoning** - AI-powered analysis
6. **Approval** - Human approval for high-risk operations
7. **Execution** - Tool execution through MCP
8. **Analysis** - Result interpretation
9. **Reporting** - Finding generation

### 2. AI Agents

#### Web Reasoning Agent (`backend/agents/web_agent.py`)

Implements Shannon-inspired "Proof by Exploitation" methodology:

```
1. IDENTIFY attack surface
2. HYPOTHESIZE vulnerabilities
3. TEST with minimal payloads
4. PROVE with evidence
5. DOCUMENT findings
```

**Specializations:**
- OWASP Top 10 vulnerabilities
- SQL injection detection
- XSS testing
- Authentication bypass
- Business logic flaws

#### Network Reasoning Agent (`backend/agents/network_agent.py`)

PentestGPT-inspired approach for network/infrastructure testing:

```
1. RECONNAISSANCE - Information gathering
2. ENUMERATION - Service identification
3. VULNERABILITY ANALYSIS - CVE mapping
4. EXPLOITATION PLANNING - Attack strategy
5. POST-EXPLOITATION - Lateral movement
```

**Specializations:**
- Port scanning strategy
- Service fingerprinting
- Known vulnerability mapping
- Credential attacks
- Protocol exploitation

### 3. Memory System

The knowledge graph (`backend/memory/`) provides temporal, semantic memory:

**Entity Types:**
- HOST - IP addresses, hostnames
- SERVICE - Running services
- VULNERABILITY - Discovered vulns
- CREDENTIAL - Found credentials
- ENDPOINT - Web endpoints
- FINDING - Security findings

**Relationships:**
- HOSTS - Host → Service
- EXPOSES - Host → Port
- HAS_VULNERABILITY - Entity → Vulnerability
- LEADS_TO - Finding → Finding (attack chains)

**Temporal Features:**
- Point-in-time queries
- Entity versioning
- Episode recording

### 4. MCP Execution Engine

The Model Control Protocol engine (`backend/tools/mcp_engine.py`) standardizes tool execution:

**Features:**
- Tool registration and discovery
- Permission checking
- Rate limiting
- Result parsing
- Audit logging

**Tool Integration Pattern:**
```python
class ToolName(CommandTool):
    name = "tool_name"
    description = "..."
    category = ToolCategory.SCANNING
    risk_level = "medium"

    def get_command(self, target, options):
        # Build command

    def parse_output(self, output):
        # Parse results
```

### 5. Database Layer

SQLite with async support for local storage:

**Tables:**
- sessions - Pentesting sessions
- targets - Target systems
- tasks - Workflow tasks
- findings - Security findings
- audit_logs - Activity logging
- settings - User preferences

### 6. API Layer

FastAPI-based REST API with WebSocket support:

**REST Endpoints:**
- `/api/sessions` - Session management
- `/api/targets` - Target management
- `/api/tasks` - Task management
- `/api/findings` - Finding management
- `/api/tools` - Tool execution
- `/api/settings` - Configuration

**WebSocket:**
- Real-time progress updates
- Finding notifications
- Approval requests

## Data Flow

```
User Input
    │
    ▼
┌──────────────────┐
│   Frontend UI    │
└────────┬─────────┘
         │ HTTP/WebSocket
         ▼
┌──────────────────┐
│   FastAPI API    │──────────────┐
└────────┬─────────┘              │
         │                        ▼
         ▼               ┌────────────────┐
┌──────────────────┐     │    SQLite DB   │
│   Orchestrator   │     └────────────────┘
└────────┬─────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│Web Agt│ │Net Agt│
└───┬───┘ └───┬───┘
    │         │
    └────┬────┘
         ▼
┌──────────────────┐
│   MCP Engine     │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Security Tools  │
│ nmap,nikto,etc   │
└──────────────────┘
```

## Security Architecture

### Authorization Flow

```
Target Added
    │
    ▼
┌──────────────────┐
│ Authorization    │
│ Required?        │
└────────┬─────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
   Yes       No (disabled)
    │         │
    ▼         │
┌───────────┐ │
│ User Auth │ │
│ Required  │ │
└─────┬─────┘ │
      │       │
      ▼       ▼
┌──────────────────┐
│ Testing Allowed  │
└──────────────────┘
```

### Approval Flow

```
Task Created
    │
    ▼
┌──────────────────┐
│ Check Risk Level │
└────────┬─────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
  Low/Med    High/Critical
    │         │
    ▼         ▼
┌───────┐  ┌─────────────┐
│ Auto  │  │ Request     │
│Execute│  │ Approval    │
└───┬───┘  └──────┬──────┘
    │             │
    │       ┌─────┴─────┐
    │       │           │
    │       ▼           ▼
    │    Approved    Rejected
    │       │           │
    │       ▼           ▼
    │    Execute      Skip
    │       │           │
    └───────┴─────┬─────┘
                  │
                  ▼
            ┌──────────┐
            │ Continue │
            └──────────┘
```

## Extensibility

### Adding New Tools

1. Create tool class in `backend/tools/`:
```python
from .base import CommandTool, ToolCategory

class NewTool(CommandTool):
    name = "newtool"
    description = "Description"
    category = ToolCategory.SCANNING
    risk_level = "medium"

    def validate_target(self, target):
        return True

    def get_command(self, target, options):
        return f"newtool {target}"

    def parse_output(self, output):
        return {"raw": output}
```

2. Register in `backend/tools/kali_tools.py`:
```python
KALI_TOOLS.append(NewTool)
```

### Adding New Agents

1. Create agent class in `backend/agents/`:
```python
from .base import BaseAgent, AgentResponse

class NewAgent(BaseAgent):
    name = "new_agent"
    specialization = "specific_domain"

    async def analyze(self, state):
        # Implement reasoning
        return AgentResponse(...)

    async def execute_action(self, action, state):
        # Implement execution
        return result

    async def analyze_result(self, result, state):
        # Generate findings
        return findings
```

2. Register with orchestrator in `backend/api/main.py`

### Adding New Workflows

Create workflow in `backend/core/workflow.py`:
```python
def _create_custom_workflow(orchestrator):
    workflow = StateGraph(PentestState)
    # Add nodes and edges
    return workflow
```

## Performance Considerations

- **Async Operations**: All I/O operations are async
- **Connection Pooling**: Database connections are pooled
- **Rate Limiting**: Tool execution is rate-limited
- **Lazy Loading**: Components load on demand
- **Caching**: Query results are cached

## Testing Strategy

- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing
- **API Tests**: Endpoint validation
- **Agent Tests**: AI reasoning validation
