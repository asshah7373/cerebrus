# Cerebrus User Guide

## Getting Started

### First Launch

1. Start Cerebrus using the run script:
   ```bash
   ./scripts/run.sh
   ```

2. Open `http://localhost:3000` in your browser

3. You'll see the Dashboard with:
   - Session statistics
   - Recent sessions
   - Findings summary
   - Quick actions

### Understanding the Interface

#### Navigation

- **Dashboard**: Overview and quick stats
- **Sessions**: Create and manage pentests
- **Tools**: View available security tools
- **Settings**: Configure behavior

#### Status Indicators

| Color | Meaning |
|-------|---------|
| 🟢 Green | Active/Running |
| 🔵 Blue | Completed |
| 🟡 Yellow | Paused/Pending |
| 🔴 Red | Failed/Critical |

## Creating a Pentest Session

### Step 1: Create Session

1. Go to **Sessions** page
2. Click **New Session**
3. Fill in:
   - **Name**: Descriptive session name
   - **Objective**: What you're testing for
   - **Target** (optional): Initial target URL/IP

### Step 2: Add Targets

1. Open your session
2. Go to **Targets** tab
3. Click **Add Target**
4. Enter:
   - Target name
   - Address (URL or IP)
   - Type (web/network/api)

### Step 3: Authorize Targets

⚠️ **Important**: You must authorize each target before testing

1. Click **Authorize** on each target
2. Enter authorization scope (what you're allowed to test)
3. Confirm authorization

### Step 4: Start Session

1. Click **Start** on the session
2. The AI will begin planning attacks
3. Low-risk tasks execute automatically
4. High-risk tasks wait for approval

## Approval Workflow

When a high-risk operation is proposed:

1. You'll see an **Approval Required** notification
2. The task details show:
   - Operation name
   - Tool to be used
   - Risk level
   - Target
3. Choose:
   - **Approve**: Execute the operation
   - **Reject**: Skip this operation

### Risk Levels

| Level | Description | Auto-Execute |
|-------|-------------|--------------|
| Low | Passive reconnaissance | ✅ |
| Medium | Active scanning | ⚙️ Configurable |
| High | Exploitation attempts | ❌ |
| Critical | Destructive operations | ❌ |

## Understanding Findings

### Severity Ratings

| Severity | Description | CVSS Range |
|----------|-------------|------------|
| Critical | Immediate exploitation risk | 9.0-10.0 |
| High | Significant security issue | 7.0-8.9 |
| Medium | Moderate risk | 4.0-6.9 |
| Low | Minor issue | 0.1-3.9 |
| Info | Informational finding | N/A |

### Finding Details

Each finding includes:
- **Title**: Brief description
- **Severity**: Risk level
- **Category**: Vulnerability type (e.g., XSS, SQLi)
- **Description**: Detailed explanation
- **Evidence**: Proof of vulnerability
- **Remediation**: How to fix it
- **CVE IDs**: Related CVEs (if any)

### Verifying Findings

1. Review the finding details
2. Check the evidence
3. Click **Verify** to confirm
4. Add notes if needed

## Session Management

### Session States

| State | Description |
|-------|-------------|
| Created | Session initialized |
| Running | Actively testing |
| Paused | Temporarily stopped |
| Completed | All tasks finished |
| Failed | Error occurred |

### Controls

- **Start**: Begin or resume testing
- **Pause**: Temporarily stop (can resume)
- **Stop**: End and complete session
- **Delete**: Remove session and data

## Real-Time Updates

### WebSocket Connection

The session view shows live updates:
- Task progress
- New findings
- Approval requests
- Agent reasoning

The 🟢 **Live** indicator shows connection status.

### Logs View

The **Logs** tab shows:
- Raw WebSocket messages
- Tool output
- Agent decisions
- Errors

## Tools Overview

### Available Tools

| Tool | Category | Risk | Description |
|------|----------|------|-------------|
| nmap | Scanning | Medium | Port/service scanner |
| nikto | Web | Medium | Web vulnerability scanner |
| gobuster | Enumeration | Low | Directory brute-forcing |
| hydra | Credential | High | Password cracker |
| sqlmap | Web | High | SQL injection tool |

### Tool Execution

Tools can be:
- Automatically selected by AI agents
- Manually triggered via API
- Chained for complex attacks

## Settings Configuration

### Automation Settings

**Automation Level**:
- Manual: All operations need approval
- Semi-Auto: Low-risk auto-executes
- Full-Auto: All auto-execute

**Max Risk Auto**:
- Set maximum risk level for auto-execution
- Higher settings reduce control

### Security Settings

**Require Authorization**:
- When enabled, targets must be authorized
- Recommended: Keep enabled

### Performance Settings

**Max Concurrent Scans**:
- Limit parallel operations
- Higher = faster but more resource use

**Request Delay**:
- Delay between requests
- Helps avoid rate limiting

## Best Practices

### Before Testing

1. ✅ Obtain written authorization
2. ✅ Define scope clearly
3. ✅ Set appropriate automation level
4. ✅ Review tool configurations

### During Testing

1. 📋 Monitor approval requests
2. 📋 Review findings as they appear
3. 📋 Check logs for errors
4. 📋 Pause if issues arise

### After Testing

1. 📝 Review all findings
2. 📝 Verify critical issues
3. 📝 Export report
4. 📝 Clean up session data

## Troubleshooting

### Common Issues

**Session Won't Start**
- Check target authorization
- Verify API keys in .env
- Check tool availability

**No Tools Found**
- Ensure Kali tools installed
- Check tool paths in settings

**WebSocket Disconnects**
- Check network connection
- Refresh the page
- Restart backend if needed

**High CPU/Memory**
- Reduce concurrent scans
- Increase request delay
- Check for stuck processes

### Getting Help

1. Check logs in `logs/cerebrus.log`
2. Review audit log at `logs/audit.log`
3. Check API health at `/health`
4. Review documentation in `/docs`
