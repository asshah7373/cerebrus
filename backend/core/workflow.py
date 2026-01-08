"""
Workflow Factory for Cerebrus
Creates and configures LangGraph workflows for different pentesting scenarios.
"""
from typing import Optional, Callable, List
from langgraph.graph import StateGraph
from .state import PentestState
from .orchestrator import PentestOrchestrator


def create_pentest_workflow(
    scenario: str = "full",
    custom_nodes: Optional[List[Callable]] = None
) -> StateGraph:
    """
    Factory function to create pentesting workflows.

    Args:
        scenario: The workflow scenario to create
            - "full": Complete pentesting workflow
            - "recon": Reconnaissance-only workflow
            - "web": Web application focused workflow
            - "network": Network focused workflow
            - "ctf": CTF-optimized workflow
        custom_nodes: Optional list of custom node functions to add

    Returns:
        Configured StateGraph ready for compilation
    """
    orchestrator = PentestOrchestrator()

    if scenario == "full":
        return orchestrator.build_workflow()

    elif scenario == "recon":
        return _create_recon_workflow(orchestrator)

    elif scenario == "web":
        return _create_web_workflow(orchestrator)

    elif scenario == "network":
        return _create_network_workflow(orchestrator)

    elif scenario == "ctf":
        return _create_ctf_workflow(orchestrator)

    else:
        raise ValueError(f"Unknown workflow scenario: {scenario}")


def _create_recon_workflow(orchestrator: PentestOrchestrator) -> StateGraph:
    """Create a reconnaissance-only workflow (low risk, no exploitation)."""
    from langgraph.graph import END

    workflow = StateGraph(PentestState)

    # Recon-specific nodes
    workflow.add_node("initialize", orchestrator._initialize_node)
    workflow.add_node("passive_recon", _passive_recon_node)
    workflow.add_node("active_recon", _active_recon_node)
    workflow.add_node("enumerate", _enumerate_node)
    workflow.add_node("report", orchestrator._generate_report_node)

    workflow.set_entry_point("initialize")
    workflow.add_edge("initialize", "passive_recon")
    workflow.add_edge("passive_recon", "active_recon")
    workflow.add_edge("active_recon", "enumerate")
    workflow.add_edge("enumerate", "report")
    workflow.add_edge("report", END)

    return workflow


def _create_web_workflow(orchestrator: PentestOrchestrator) -> StateGraph:
    """Create a web application focused workflow."""
    from langgraph.graph import END

    workflow = StateGraph(PentestState)

    workflow.add_node("initialize", orchestrator._initialize_node)
    workflow.add_node("check_authorization", orchestrator._check_authorization_node)
    workflow.add_node("web_recon", _web_recon_node)
    workflow.add_node("spider", _spider_node)
    workflow.add_node("vulnerability_scan", _vuln_scan_node)
    workflow.add_node("manual_testing", orchestrator._web_reasoning_node)
    workflow.add_node("request_approval", orchestrator._request_approval_node)
    workflow.add_node("exploit", orchestrator._execute_task_node)
    workflow.add_node("report", orchestrator._generate_report_node)

    workflow.set_entry_point("initialize")
    workflow.add_edge("initialize", "check_authorization")

    workflow.add_conditional_edges(
        "check_authorization",
        orchestrator._route_authorization,
        {
            "authorized": "web_recon",
            "unauthorized": END,
            "pending": "request_approval"
        }
    )

    workflow.add_edge("web_recon", "spider")
    workflow.add_edge("spider", "vulnerability_scan")
    workflow.add_edge("vulnerability_scan", "manual_testing")

    workflow.add_conditional_edges(
        "manual_testing",
        orchestrator._check_approval_required,
        {
            "needs_approval": "request_approval",
            "approved": "exploit"
        }
    )

    workflow.add_edge("exploit", "report")
    workflow.add_edge("report", END)

    return workflow


def _create_network_workflow(orchestrator: PentestOrchestrator) -> StateGraph:
    """Create a network focused workflow."""
    from langgraph.graph import END

    workflow = StateGraph(PentestState)

    workflow.add_node("initialize", orchestrator._initialize_node)
    workflow.add_node("check_authorization", orchestrator._check_authorization_node)
    workflow.add_node("host_discovery", _host_discovery_node)
    workflow.add_node("port_scan", _port_scan_node)
    workflow.add_node("service_enum", _service_enum_node)
    workflow.add_node("vuln_assessment", _vuln_assessment_node)
    workflow.add_node("network_reasoning", orchestrator._network_reasoning_node)
    workflow.add_node("request_approval", orchestrator._request_approval_node)
    workflow.add_node("exploit", orchestrator._execute_task_node)
    workflow.add_node("report", orchestrator._generate_report_node)

    workflow.set_entry_point("initialize")
    workflow.add_edge("initialize", "check_authorization")

    workflow.add_conditional_edges(
        "check_authorization",
        orchestrator._route_authorization,
        {
            "authorized": "host_discovery",
            "unauthorized": END,
            "pending": "request_approval"
        }
    )

    workflow.add_edge("host_discovery", "port_scan")
    workflow.add_edge("port_scan", "service_enum")
    workflow.add_edge("service_enum", "vuln_assessment")
    workflow.add_edge("vuln_assessment", "network_reasoning")

    workflow.add_conditional_edges(
        "network_reasoning",
        orchestrator._check_approval_required,
        {
            "needs_approval": "request_approval",
            "approved": "exploit"
        }
    )

    workflow.add_edge("exploit", "report")
    workflow.add_edge("report", END)

    return workflow


def _create_ctf_workflow(orchestrator: PentestOrchestrator) -> StateGraph:
    """Create a CTF-optimized workflow with aggressive automation."""
    from langgraph.graph import END

    workflow = StateGraph(PentestState)

    workflow.add_node("initialize", orchestrator._initialize_node)
    workflow.add_node("quick_scan", _quick_scan_node)
    workflow.add_node("identify_challenge", _identify_challenge_node)
    workflow.add_node("web_path", orchestrator._web_reasoning_node)
    workflow.add_node("network_path", orchestrator._network_reasoning_node)
    workflow.add_node("execute", orchestrator._execute_task_node)
    workflow.add_node("capture_flag", _capture_flag_node)

    workflow.set_entry_point("initialize")
    workflow.add_edge("initialize", "quick_scan")
    workflow.add_edge("quick_scan", "identify_challenge")

    workflow.add_conditional_edges(
        "identify_challenge",
        _route_challenge_type,
        {
            "web": "web_path",
            "network": "network_path",
            "execute": "execute"
        }
    )

    workflow.add_edge("web_path", "execute")
    workflow.add_edge("network_path", "execute")
    workflow.add_edge("execute", "capture_flag")
    workflow.add_edge("capture_flag", END)

    return workflow


# Workflow-specific node functions

async def _passive_recon_node(state: PentestState) -> dict:
    """Passive reconnaissance node."""
    return {
        "workflow_phase": "passive_recon",
        "messages": [{
            "role": "system",
            "content": "Performing passive reconnaissance (WHOIS, DNS, OSINT)"
        }]
    }


async def _active_recon_node(state: PentestState) -> dict:
    """Active reconnaissance node."""
    return {
        "workflow_phase": "active_recon",
        "messages": [{
            "role": "system",
            "content": "Performing active reconnaissance"
        }]
    }


async def _enumerate_node(state: PentestState) -> dict:
    """Enumeration node."""
    return {
        "workflow_phase": "enumeration",
        "messages": [{
            "role": "system",
            "content": "Enumerating discovered assets"
        }]
    }


async def _web_recon_node(state: PentestState) -> dict:
    """Web reconnaissance node."""
    return {
        "workflow_phase": "web_recon",
        "messages": [{
            "role": "system",
            "content": "Performing web application reconnaissance"
        }]
    }


async def _spider_node(state: PentestState) -> dict:
    """Web spidering node."""
    return {
        "workflow_phase": "spidering",
        "messages": [{
            "role": "system",
            "content": "Spidering web application"
        }]
    }


async def _vuln_scan_node(state: PentestState) -> dict:
    """Vulnerability scanning node."""
    return {
        "workflow_phase": "vuln_scan",
        "messages": [{
            "role": "system",
            "content": "Running vulnerability scanners"
        }]
    }


async def _host_discovery_node(state: PentestState) -> dict:
    """Host discovery node."""
    return {
        "workflow_phase": "host_discovery",
        "messages": [{
            "role": "system",
            "content": "Discovering hosts on network"
        }]
    }


async def _port_scan_node(state: PentestState) -> dict:
    """Port scanning node."""
    return {
        "workflow_phase": "port_scan",
        "messages": [{
            "role": "system",
            "content": "Scanning ports"
        }]
    }


async def _service_enum_node(state: PentestState) -> dict:
    """Service enumeration node."""
    return {
        "workflow_phase": "service_enum",
        "messages": [{
            "role": "system",
            "content": "Enumerating services"
        }]
    }


async def _vuln_assessment_node(state: PentestState) -> dict:
    """Vulnerability assessment node."""
    return {
        "workflow_phase": "vuln_assessment",
        "messages": [{
            "role": "system",
            "content": "Assessing vulnerabilities"
        }]
    }


async def _quick_scan_node(state: PentestState) -> dict:
    """Quick CTF scan node."""
    return {
        "workflow_phase": "quick_scan",
        "messages": [{
            "role": "system",
            "content": "Performing quick CTF scan"
        }]
    }


async def _identify_challenge_node(state: PentestState) -> dict:
    """Identify CTF challenge type."""
    return {
        "workflow_phase": "identify_challenge",
        "next_action": "web",  # Default, would be AI-determined
        "messages": [{
            "role": "system",
            "content": "Identifying challenge type"
        }]
    }


async def _capture_flag_node(state: PentestState) -> dict:
    """Capture flag node."""
    return {
        "workflow_phase": "capture_flag",
        "messages": [{
            "role": "system",
            "content": "Attempting to capture flag"
        }]
    }


def _route_challenge_type(state: PentestState) -> str:
    """Route based on identified challenge type."""
    return state.next_action or "network"
