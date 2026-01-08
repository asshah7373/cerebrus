# Cerebrus API Reference

## Base URL

```
http://localhost:8000
```

## Authentication

Currently, Cerebrus runs locally without authentication. Future versions will support API keys.

## Response Format

All responses are JSON:

```json
{
  "data": {},
  "error": null
}
```

Error responses:

```json
{
  "detail": "Error message"
}
```

---

## Sessions

### Create Session

```http
POST /api/sessions
```

**Request Body:**
```json
{
  "name": "Web App Assessment",
  "objective": "Find vulnerabilities in the target web application",
  "targets": [
    {
      "name": "Main Site",
      "address": "https://example.com",
      "type": "web"
    }
  ],
  "constraints": ["No destructive testing"],
  "automation_level": "semi_auto"
}
```

**Response:**
```json
{
  "id": "uuid",
  "name": "Web App Assessment",
  "objective": "...",
  "status": "created",
  "automation_level": "semi_auto",
  "created_at": "2024-01-15T10:00:00Z"
}
```

### List Sessions

```http
GET /api/sessions?limit=50&offset=0&status=running
```

**Query Parameters:**
- `limit` (int): Max results (default: 50)
- `offset` (int): Pagination offset
- `status` (string): Filter by status

**Response:**
```json
{
  "sessions": [...],
  "total": 10
}
```

### Get Session

```http
GET /api/sessions/{session_id}
```

**Response:**
```json
{
  "id": "uuid",
  "name": "...",
  "objective": "...",
  "status": "running",
  "target_count": 3,
  "finding_count": 5,
  "created_at": "...",
  "started_at": "..."
}
```

### Start Session

```http
POST /api/sessions/{session_id}/start
```

**Response:**
```json
{
  "status": "started",
  "session_id": "uuid"
}
```

### Pause Session

```http
POST /api/sessions/{session_id}/pause
```

### Stop Session

```http
POST /api/sessions/{session_id}/stop
```

### Delete Session

```http
DELETE /api/sessions/{session_id}
```

### Get Session State

```http
GET /api/sessions/{session_id}/state
```

**Response:**
```json
{
  "session_id": "uuid",
  "workflow_phase": "scanning",
  "current_agent": "web_agent",
  "current_task_id": "uuid",
  "pending_tasks": 5,
  "completed_tasks": 10,
  "finding_count": 3,
  "requires_input": false
}
```

---

## Targets

### Create Target

```http
POST /api/targets
```

**Request Body:**
```json
{
  "session_id": "uuid",
  "name": "Main Application",
  "target_type": "web",
  "address": "https://example.com",
  "ports": [80, 443],
  "notes": "Production server"
}
```

### List Session Targets

```http
GET /api/targets/session/{session_id}
```

### Get Target

```http
GET /api/targets/{target_id}
```

### Authorize Target

```http
POST /api/targets/{target_id}/authorize
```

**Request Body:**
```json
{
  "authorization_scope": "Full web application testing, excluding DoS",
  "authorized_by": "admin"
}
```

### Revoke Authorization

```http
POST /api/targets/{target_id}/revoke
```

### Delete Target

```http
DELETE /api/targets/{target_id}
```

---

## Tasks

### Create Task

```http
POST /api/tasks
```

**Request Body:**
```json
{
  "session_id": "uuid",
  "target_id": "uuid",
  "name": "Port Scan",
  "task_type": "scan",
  "tool": "nmap",
  "parameters": {
    "scan_type": "comprehensive"
  },
  "risk_level": "medium"
}
```

### List Session Tasks

```http
GET /api/tasks/session/{session_id}?status=pending
```

### Get Task

```http
GET /api/tasks/{task_id}
```

### Approve Task

```http
POST /api/tasks/{task_id}/approve
```

**Request Body:**
```json
{
  "approved": true,
  "approved_by": "admin"
}
```

### Get Pending Approvals

```http
GET /api/tasks/pending-approvals/{session_id}
```

**Response:**
```json
{
  "pending_approvals": [
    {
      "task_id": "uuid",
      "name": "SQL Injection Test",
      "task_type": "exploit",
      "tool": "sqlmap",
      "risk_level": "high"
    }
  ],
  "count": 1
}
```

---

## Findings

### Create Finding

```http
POST /api/findings
```

**Request Body:**
```json
{
  "session_id": "uuid",
  "target_id": "uuid",
  "title": "SQL Injection in Login Form",
  "description": "The login form is vulnerable to SQL injection...",
  "severity": "critical",
  "category": "Injection",
  "evidence": "Input: ' OR '1'='1 returned all users",
  "remediation": "Use parameterized queries",
  "cve_ids": ["CVE-2021-12345"],
  "cvss_score": 9.8
}
```

### List Session Findings

```http
GET /api/findings/session/{session_id}?severity=critical&verified=true
```

### Get Findings Summary

```http
GET /api/findings/session/{session_id}/summary
```

**Response:**
```json
{
  "total": 15,
  "critical": 2,
  "high": 5,
  "medium": 4,
  "low": 3,
  "info": 1,
  "verified": 7,
  "unverified": 8
}
```

### Verify Finding

```http
POST /api/findings/{finding_id}/verify
```

**Request Body:**
```json
{
  "verified": true,
  "verified_by": "security_analyst"
}
```

### Export Findings

```http
GET /api/findings/session/{session_id}/export?format=json
```

Formats: `json`, `markdown`

---

## Tools

### List Tools

```http
GET /api/tools?category=web&max_risk=medium
```

**Response:**
```json
{
  "tools": [
    {
      "name": "nikto",
      "description": "Web vulnerability scanner",
      "category": "web",
      "risk_level": "medium",
      "requires_root": false,
      "options_schema": {...}
    }
  ],
  "total": 5
}
```

### Get Tool Details

```http
GET /api/tools/{tool_name}
```

### Execute Tool

```http
POST /api/tools/execute
```

**Request Body:**
```json
{
  "tool_name": "nmap",
  "target": "192.168.1.1",
  "options": {
    "scan_type": "comprehensive",
    "ports": "1-1000"
  },
  "session_id": "uuid"
}
```

**Response (Success):**
```json
{
  "status": "success",
  "output": "...",
  "parsed_data": {...},
  "execution_time_ms": 5000
}
```

**Response (Pending Approval):**
```json
{
  "status": "pending_approval",
  "request_id": "uuid",
  "reason": "Tool risk level exceeds auto-approve threshold"
}
```

### Approve Execution

```http
POST /api/tools/approve/{request_id}?approved=true
```

### Get Execution History

```http
GET /api/tools/history?limit=100
```

### Get Tool Categories

```http
GET /api/tools/categories
```

---

## Settings

### Get All Settings

```http
GET /api/settings
```

### Get Setting

```http
GET /api/settings/{key}
```

### Update Setting

```http
PUT /api/settings/{key}
```

**Request Body:**
```json
{
  "value": "semi_auto",
  "description": "Automation level setting"
}
```

### Delete Setting (Reset to Default)

```http
DELETE /api/settings/{key}
```

### Reset All Settings

```http
POST /api/settings/reset
```

### Get Risk Level Info

```http
GET /api/settings/risk-levels/info
```

---

## WebSocket

### Connect

```javascript
const ws = new WebSocket('ws://localhost:8000/api/sessions/{session_id}/ws');
```

### Message Types

**Progress Update:**
```json
{
  "type": "progress",
  "task_id": "uuid",
  "progress": 50,
  "status": "in_progress",
  "message": "Scanning ports..."
}
```

**Finding Discovered:**
```json
{
  "type": "finding",
  "finding": {
    "id": "uuid",
    "title": "...",
    "severity": "high"
  }
}
```

**Approval Request:**
```json
{
  "type": "approval_request",
  "request_id": "uuid",
  "task_name": "SQL Injection Test",
  "risk_level": "high",
  "description": "..."
}
```

**Error:**
```json
{
  "type": "error",
  "error": "Error message",
  "task_id": "uuid"
}
```

### Client Messages

**Approve Task:**
```json
{
  "type": "approve",
  "task_id": "uuid",
  "approved": true
}
```

**Ping:**
```json
{
  "type": "ping"
}
```

---

## Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "components": {
    "database": "connected",
    "mcp_engine": "ready",
    "orchestrator": "ready"
  }
}
```

---

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - State conflict |
| 500 | Internal Error - Server error |
| 503 | Service Unavailable - Component not ready |
