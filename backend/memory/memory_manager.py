"""
Memory Manager
High-level interface for the memory system, integrating with the knowledge graph.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
import structlog

from .knowledge_graph import KnowledgeGraph
from .entities import (
    Entity, Relationship, Episode,
    EntityType, RelationType,
    HostEntity, ServiceEntity, VulnerabilityEntity
)

logger = structlog.get_logger()


class MemoryManager:
    """
    High-level memory management for the pentesting workflow.

    Provides semantic operations for storing and retrieving pentesting
    information, abstracting the underlying knowledge graph.
    """

    def __init__(self):
        self.graph = KnowledgeGraph()
        logger.info("Memory manager initialized")

    async def remember_host(
        self,
        session_id: str,
        ip_address: str,
        hostname: Optional[str] = None,
        os: Optional[str] = None,
        source: str = "scan"
    ) -> HostEntity:
        """
        Remember a discovered host.

        Args:
            session_id: Current session ID
            ip_address: IP address of the host
            hostname: Optional hostname
            os: Optional OS identification
            source: Discovery source

        Returns:
            The created host entity
        """
        # Check if host already exists
        existing = self.find_host(ip_address)
        if existing:
            # Update existing host
            existing.update({
                "hostname": hostname or existing.attributes.get("hostname"),
                "os": os or existing.attributes.get("os")
            })
            return existing

        host = HostEntity(
            name=hostname or ip_address,
            attributes={
                "ip_address": ip_address,
                "hostname": hostname,
                "os": os
            },
            source=source,
            session_id=session_id
        )

        self.graph.add_entity(host)

        logger.info(
            "Host remembered",
            ip_address=ip_address,
            hostname=hostname
        )

        return host

    async def remember_service(
        self,
        session_id: str,
        host_id: str,
        port: int,
        service_name: str,
        version: Optional[str] = None,
        protocol: str = "tcp",
        source: str = "scan"
    ) -> ServiceEntity:
        """
        Remember a discovered service on a host.

        Args:
            session_id: Current session ID
            host_id: ID of the host running the service
            port: Port number
            service_name: Name of the service
            version: Optional version string
            protocol: Protocol (tcp/udp)
            source: Discovery source

        Returns:
            The created service entity
        """
        service = ServiceEntity(
            name=f"{service_name}:{port}",
            attributes={
                "service_name": service_name,
                "port": port,
                "version": version,
                "protocol": protocol
            },
            source=source,
            session_id=session_id
        )

        self.graph.add_entity(service)

        # Create relationship to host
        relationship = Relationship(
            relation_type=RelationType.RUNS_ON,
            source_id=service.id,
            target_id=host_id
        )
        self.graph.add_relationship(relationship)

        # Also create HOSTS relationship from host to service
        hosts_rel = Relationship(
            relation_type=RelationType.HOSTS,
            source_id=host_id,
            target_id=service.id
        )
        self.graph.add_relationship(hosts_rel)

        logger.info(
            "Service remembered",
            service=service_name,
            port=port,
            host_id=host_id
        )

        return service

    async def remember_vulnerability(
        self,
        session_id: str,
        target_id: str,
        title: str,
        severity: str,
        cve_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        description: str = "",
        evidence: str = "",
        source: str = "scan"
    ) -> VulnerabilityEntity:
        """
        Remember a discovered vulnerability.

        Args:
            session_id: Current session ID
            target_id: ID of the affected entity (host or service)
            title: Vulnerability title
            severity: Severity level
            cve_id: Optional CVE identifier
            cvss_score: Optional CVSS score
            description: Vulnerability description
            evidence: Proof of vulnerability
            source: Discovery source

        Returns:
            The created vulnerability entity
        """
        vuln = VulnerabilityEntity(
            name=title,
            attributes={
                "severity": severity,
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "description": description,
                "evidence": evidence,
                "exploitable": False  # Will be updated if exploited
            },
            source=source,
            session_id=session_id
        )

        self.graph.add_entity(vuln)

        # Create relationship to target
        relationship = Relationship(
            relation_type=RelationType.HAS_VULNERABILITY,
            source_id=target_id,
            target_id=vuln.id
        )
        self.graph.add_relationship(relationship)

        logger.info(
            "Vulnerability remembered",
            title=title,
            severity=severity,
            cve_id=cve_id
        )

        return vuln

    async def record_episode(
        self,
        session_id: str,
        name: str,
        description: str,
        episode_type: str,
        entity_ids: List[str] = None,
        tool_used: Optional[str] = None,
        command: Optional[str] = None,
        raw_output: Optional[str] = None,
        success: bool = True,
        findings: List[str] = None
    ) -> Episode:
        """
        Record an episode (discrete event in the pentest).

        Args:
            session_id: Current session ID
            name: Episode name
            description: What happened
            episode_type: Type of episode
            entity_ids: Related entity IDs
            tool_used: Tool that was used
            command: Command that was executed
            raw_output: Raw output from the command
            success: Whether the episode was successful
            findings: List of finding descriptions

        Returns:
            The created episode
        """
        episode = Episode(
            session_id=session_id,
            name=name,
            description=description,
            episode_type=episode_type,
            entity_ids=entity_ids or [],
            tool_used=tool_used,
            command=command,
            raw_output=raw_output,
            success=success,
            findings=findings or []
        )

        self.graph.add_episode(episode)

        logger.info(
            "Episode recorded",
            name=name,
            episode_type=episode_type,
            success=success
        )

        return episode

    def find_host(self, identifier: str) -> Optional[HostEntity]:
        """
        Find a host by IP address or hostname.

        Args:
            identifier: IP address or hostname

        Returns:
            Host entity if found
        """
        hosts = self.graph.get_entities_by_type(EntityType.HOST)

        for host in hosts:
            if host.attributes.get("ip_address") == identifier:
                return host
            if host.attributes.get("hostname") == identifier:
                return host

        return None

    def get_host_services(self, host_id: str) -> List[ServiceEntity]:
        """Get all services running on a host."""
        related = self.graph.get_related_entities(
            host_id,
            RelationType.HOSTS,
            direction="outgoing"
        )
        return [entity for entity, _ in related if entity.entity_type == EntityType.SERVICE]

    def get_host_vulnerabilities(self, host_id: str) -> List[VulnerabilityEntity]:
        """Get all vulnerabilities for a host (including service vulns)."""
        vulns = self.graph.get_vulnerabilities_for_host(host_id)
        return vulns

    def get_attack_chain(
        self,
        start_entity_id: str,
        end_entity_id: str
    ) -> List[List[Entity]]:
        """
        Find attack chains between two entities.

        Args:
            start_entity_id: Starting point
            end_entity_id: Target

        Returns:
            List of attack paths (each path is a list of entities)
        """
        paths = self.graph.find_attack_paths(start_entity_id, end_entity_id)

        # Convert paths from IDs to entities
        entity_paths = []
        for path in paths:
            entity_path = [
                self.graph.get_entity(entity_id)
                for entity_id in path
            ]
            if all(entity_path):  # All entities found
                entity_paths.append(entity_path)

        return entity_paths

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """
        Get a summary of findings for a session.

        Args:
            session_id: Session ID

        Returns:
            Summary dictionary
        """
        entities = self.graph.get_entities_by_session(session_id)

        hosts = [e for e in entities if e.entity_type == EntityType.HOST]
        services = [e for e in entities if e.entity_type == EntityType.SERVICE]
        vulns = [e for e in entities if e.entity_type == EntityType.VULNERABILITY]

        # Categorize vulnerabilities by severity
        vuln_by_severity = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": []
        }

        for vuln in vulns:
            severity = vuln.attributes.get("severity", "info").lower()
            if severity in vuln_by_severity:
                vuln_by_severity[severity].append(vuln)

        return {
            "session_id": session_id,
            "total_hosts": len(hosts),
            "total_services": len(services),
            "total_vulnerabilities": len(vulns),
            "vulnerabilities_by_severity": {
                k: len(v) for k, v in vuln_by_severity.items()
            },
            "hosts": [
                {
                    "id": h.id,
                    "ip": h.attributes.get("ip_address"),
                    "hostname": h.attributes.get("hostname")
                }
                for h in hosts
            ],
            "critical_findings": [
                {
                    "id": v.id,
                    "title": v.name,
                    "cve": v.attributes.get("cve_id")
                }
                for v in vuln_by_severity["critical"]
            ]
        }

    def recall_similar(
        self,
        context: str,
        limit: int = 5
    ) -> List[Entity]:
        """
        Recall entities similar to the given context.
        Uses text-based search (could be enhanced with embeddings).

        Args:
            context: Context string to search for
            limit: Maximum results

        Returns:
            List of similar entities
        """
        return self.graph.search_entities(context, limit=limit)

    def get_context_for_target(
        self,
        target_id: str
    ) -> Dict[str, Any]:
        """
        Get full context for a target (host or service).

        Args:
            target_id: Entity ID

        Returns:
            Context dictionary with all related information
        """
        entity = self.graph.get_entity(target_id)
        if not entity:
            return {}

        context = {
            "entity": entity.model_dump(),
            "related_entities": [],
            "vulnerabilities": [],
            "episodes": []
        }

        # Get related entities
        related = self.graph.get_related_entities(target_id)
        for rel_entity, relationship in related:
            context["related_entities"].append({
                "entity": rel_entity.model_dump(),
                "relationship": relationship.model_dump()
            })

        # Get vulnerabilities
        if entity.entity_type == EntityType.HOST:
            vulns = self.get_host_vulnerabilities(target_id)
            context["vulnerabilities"] = [v.model_dump() for v in vulns]

        # Get episodes
        episodes = self.graph.get_episodes_for_entity(target_id)
        context["episodes"] = [ep.model_dump() for ep in episodes]

        return context

    def export_graph(self) -> str:
        """Export the entire knowledge graph to JSON."""
        return self.graph.export_to_json()

    def import_graph(self, json_str: str):
        """Import a knowledge graph from JSON."""
        self.graph.import_from_json(json_str)

    def get_statistics(self) -> Dict[str, Any]:
        """Get memory system statistics."""
        return self.graph.get_graph_statistics()

    def clear_session(self, session_id: str):
        """Clear all data for a specific session."""
        entities = self.graph.get_entities_by_session(session_id)
        for entity in entities:
            if entity.id in self.graph.entities:
                del self.graph.entities[entity.id]
                self.graph.graph.remove_node(entity.id)

        logger.info("Session cleared", session_id=session_id)
