# Cerebrus - AI-Powered Penetration Testing Tool

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue.svg" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/React-18.2-61dafb.svg" alt="React 18.2">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License">
</p>

Cerebrus is a comprehensive AI-powered penetration testing framework that combines cutting-edge AI orchestration with traditional security tools. Built with LangGraph for intelligent workflow management, it provides automated yet controlled security testing capabilities.

## Features

- **AI-Powered Orchestration**: LangGraph-based workflow engine for intelligent attack planning
- **Multi-Agent Architecture**: Specialized agents for web and network security testing
- **Shannon-Inspired Web Testing**: "Proof by Exploitation" methodology for web applications
- **PentestGPT-Style Network Analysis**: CTF-optimized network penetration testing
- **Temporal Knowledge Graph**: Graphiti-inspired memory system for context retention
- **MCP Execution Engine**: Standardized tool execution with approval workflows
- **Human-in-the-Loop Controls**: Granular approval system for high-risk operations
- **Real-time Updates**: WebSocket-based progress tracking and notifications
- **Kali Linux Integration**: Native support for nmap, nikto, hydra, gobuster, sqlmap

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        React Frontend                            │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐            │
│  │Dashboard│  │Sessions │  │ Tools   │  │Settings │            │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘            │
└───────┼────────────┼────────────┼────────────┼──────────────────┘
        │            │            │            │
        └────────────┴─────┬──────┴────────────┘
                           │ REST API / WebSocket
┌──────────────────────────┴──────────────────────────────────────┐
│                      FastAPI Backend                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                   LangGraph Orchestrator                    │ │
│  │  ┌───────────┐  ┌───────────┐  ┌───────────────────────┐  │ │
│  │  │ Web Agent │  │Net Agent  │  │  Approval Workflow    │  │ │
│  │  │ (Shannon) │  │(PentestGPT)│  │                       │  │ │
│  │  └─────┬─────┘  └─────┬─────┘  └───────────────────────┘  │ │
│  └────────┼──────────────┼───────────────────────────────────┘ │
│           │              │                                       │
│  ┌────────┴──────────────┴───────────────────────────────────┐ │
│  │                    MCP Execution Engine                    │ │
│  │  ┌──────┐ ┌──────┐ ┌───────┐ ┌─────────┐ ┌──────┐        │ │
│  │  │ nmap │ │nikto │ │gobuster│ │ hydra  │ │sqlmap│        │ │
│  │  └──────┘ └──────┘ └───────┘ └─────────┘ └──────┘        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────────────────────────┐  │
│  │  SQLite Database │  │  Knowledge Graph (Memory System)    │  │
│  └─────────────────┘  └─────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- Kali Linux (recommended) or pentesting tools installed

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/cerebrus.git
   cd cerebrus
   ```

2. **Run the setup script**
   ```bash
   chmod +x scripts/setup.sh
   ./scripts/setup.sh
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env and add your API keys
   ```

4. **Start the application**
   ```bash
   ./scripts/run.sh
   ```

5. **Open your browser**
   Navigate to `http://localhost:3000`

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t cerebrus .
docker run -p 8000:8000 -e ANTHROPIC_API_KEY=your_key cerebrus
```

## Usage

### Creating a Session

1. Navigate to the **Sessions** page
2. Click **New Session**
3. Enter:
   - Session name
   - Objective (e.g., "Find vulnerabilities in web application")
   - Initial target URL or IP
4. Click **Create Session**

### Running a Pentest

1. **Authorize Targets**: Before testing, explicitly authorize each target
2. **Start Session**: Click the Start button to begin the assessment
3. **Review Approvals**: High-risk operations will pause for your approval
4. **Monitor Progress**: Watch real-time updates in the session view
5. **Review Findings**: Check discovered vulnerabilities with severity ratings

### Security Controls

Cerebrus implements multiple security controls:

| Risk Level | Auto-Execute | Description |
|------------|--------------|-------------|
| Low        | ✅ Yes       | Passive reconnaissance |
| Medium     | ⚙️ Configurable | Active scanning |
| High       | ❌ No        | Exploitation attempts |
| Critical   | ❌ No        | Destructive operations |

## Configuration

### Automation Levels

- **Manual**: All operations require approval
- **Semi-Auto**: Low-risk operations auto-execute
- **Full-Auto**: All operations auto-execute (use with caution)

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude | Required |
| `AUTOMATION_LEVEL` | Default automation level | `semi_auto` |
| `MAX_RISK_AUTO` | Max risk for auto-execution | `low` |
| `REQUIRE_AUTHORIZATION` | Require target authorization | `true` |

## Project Structure

```
cerebrus/
├── backend/
│   ├── api/              # FastAPI routes and WebSocket
│   ├── agents/           # AI reasoning agents
│   ├── core/             # LangGraph orchestrator
│   ├── memory/           # Knowledge graph system
│   ├── models/           # Database models
│   ├── tools/            # MCP engine and tool wrappers
│   └── config.py         # Configuration
├── frontend/
│   ├── src/
│   │   ├── components/   # React components
│   │   ├── pages/        # Page components
│   │   ├── hooks/        # Custom hooks
│   │   └── utils/        # Utilities
│   └── package.json
├── scripts/              # Setup and run scripts
├── docs/                 # Documentation
├── tests/                # Unit and integration tests
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

## API Reference

### Sessions

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/sessions` | Create new session |
| GET | `/api/sessions` | List all sessions |
| GET | `/api/sessions/{id}` | Get session details |
| POST | `/api/sessions/{id}/start` | Start session |
| POST | `/api/sessions/{id}/pause` | Pause session |
| POST | `/api/sessions/{id}/stop` | Stop session |

### Targets

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/targets` | Add target |
| GET | `/api/targets/session/{id}` | List session targets |
| POST | `/api/targets/{id}/authorize` | Authorize target |

### Findings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/findings/session/{id}` | List findings |
| GET | `/api/findings/session/{id}/summary` | Get summary |
| POST | `/api/findings/{id}/verify` | Verify finding |

### WebSocket

Connect to `/api/sessions/{id}/ws` for real-time updates:

```javascript
const ws = new WebSocket('ws://localhost:8000/api/sessions/{id}/ws');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // Handle: progress, finding, approval_request, error
};
```

## Security Considerations

- **Authorization Required**: All targets must be explicitly authorized
- **Approval Workflows**: High-risk operations require human approval
- **Audit Logging**: All actions are logged for accountability
- **Local Storage**: Sensitive data stored locally in SQLite
- **No Credential Storage**: Passwords are not stored in plaintext

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest tests/`
5. Submit a pull request

## Disclaimer

**This tool is intended for authorized security testing only.**

Always obtain explicit written permission before testing any systems you do not own. Unauthorized access to computer systems is illegal. The developers assume no liability for misuse of this software.

## License

MIT License - See LICENSE file for details.

## Acknowledgments

- [LangGraph](https://github.com/langchain-ai/langgraph) - Workflow orchestration
- [Shannon](https://github.com/KeygraphHQ/shannon) - Web testing inspiration
- [PentestGPT](https://github.com/GreyDGL/PentestGPT) - Network testing patterns
- [Graphiti](https://github.com/getzep/graphiti) - Knowledge graph concepts
- [HexStrike AI](https://github.com/0x4m4/hexstrike-ai) - Architecture patterns
