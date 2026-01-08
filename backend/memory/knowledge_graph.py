"""
Knowledge Graph Implementation
Temporal knowledge graph for storing and querying pentesting information.
"""
from typing import Optional, List, Dict, Any, Set, Tuple
from datetime import datetime
import networkx as nx
import json
import structlog

from .entities import Entity, Relationship, Episode, EntityType, RelationType

logger = structlog.get_logger()


class KnowledgeGraph:
    """
    Temporal Knowledge Graph for pentesting memory.

    This implementation uses NetworkX for graph operations and supports:
    - Temporal queries (point-in-time and range queries)
    - Entity and relationship versioning
    - Episodic memory for contextual recall
    - Graph traversal for attack path analysis
    """

    def __init__(self):
        # Main graph for current state
        self.graph = nx.MultiDiGraph()

        # Storage for entities and relationships
        self.entities: Dict[str, Entity] = {}
        self.relationships: Dict[str, Relationship] = {}
        self.episodes: Dict[str, Episode] = {}

        # Indexes for fast lookup
        self.entity_type_index: Dict[EntityType, Set[str]] = {
            et: set() for et in EntityType
        }
        self.session_index: Dict[str, Set[str]] = {}

        logger.info("Knowledge graph initialized")

    def add_entity(self, entity: Entity) -> str:
        """
        Add or update an entity in the graph.

        Args:
            entity: The entity to add

        Returns:
            Entity ID
        """
        self.entities[entity.id] = entity

        # Add to graph
        self.graph.add_node(
            entity.id,
            entity_type=entity.entity_type,
            name=entity.name,
            attributes=entity.attributes,
            created_at=entity.created_at.isoformat(),
            updated_at=entity.updated_at.isoformat()
        )

        # Update indexes
        self.entity_type_index[entity.entity_type].add(entity.id)

        if entity.session_id:
            if entity.session_id not in self.session_index:
                self.session_index[entity.session_id] = set()
            self.session_index[entity.session_id].add(entity.id)

        logger.debug(
            "Entity added",
            entity_id=entity.id,
            entity_type=entity.entity_type,
            name=entity.name
        )

        return entity.id

    def add_relationship(self, relationship: Relationship) -> str:
        """
        Add a relationship between two entities.

        Args:
            relationship: The relationship to add

        Returns:
            Relationship ID
        """
        if relationship.source_id not in self.entities:
            raise ValueError(f"Source entity {relationship.source_id} not found")
        if relationship.target_id not in self.entities:
            raise ValueError(f"Target entity {relationship.target_id} not found")

        self.relationships[relationship.id] = relationship

        # Add edge to graph
        self.graph.add_edge(
            relationship.source_id,
            relationship.target_id,
            key=relationship.id,
            relation_type=relationship.relation_type,
            attributes=relationship.attributes,
            created_at=relationship.created_at.isoformat()
        )

        logger.debug(
            "Relationship added",
            relationship_id=relationship.id,
            relation_type=relationship.relation_type,
            source=relationship.source_id,
            target=relationship.target_id
        )

        return relationship.id

    def add_episode(self, episode: Episode) -> str:
        """
        Record an episode (discrete interaction event).

        Args:
            episode: The episode to record

        Returns:
            Episode ID
        """
        self.episodes[episode.id] = episode

        # Link entities to episode
        for entity_id in episode.entity_ids:
            if entity_id in self.entities:
                self.entities[entity_id].episode_ids.append(episode.id)

        logger.debug(
            "Episode recorded",
            episode_id=episode.id,
            name=episode.name,
            entity_count=len(episode.entity_ids)
        )

        return episode.id

    def get_entity(self, entity_id: str) -> Optional[Entity]:
        """Get an entity by ID."""
        return self.entities.get(entity_id)

    def get_entities_by_type(self, entity_type: EntityType) -> List[Entity]:
        """Get all entities of a specific type."""
        entity_ids = self.entity_type_index.get(entity_type, set())
        return [self.entities[eid] for eid in entity_ids if eid in self.entities]

    def get_entities_by_session(self, session_id: str) -> List[Entity]:
        """Get all entities discovered in a specific session."""
        entity_ids = self.session_index.get(session_id, set())
        return [self.entities[eid] for eid in entity_ids if eid in self.entities]

    def get_related_entities(
        self,
        entity_id: str,
        relation_type: Optional[RelationType] = None,
        direction: str = "both"
    ) -> List[Tuple[Entity, Relationship]]:
        """
        Get entities related to a given entity.

        Args:
            entity_id: The source entity ID
            relation_type: Filter by relationship type (optional)
            direction: "outgoing", "incoming", or "both"

        Returns:
            List of (entity, relationship) tuples
        """
        results = []

        if direction in ("outgoing", "both"):
            for _, target_id, key, data in self.graph.out_edges(entity_id, keys=True, data=True):
                if relation_type and data.get("relation_type") != relation_type:
                    continue
                if target_id in self.entities and key in self.relationships:
                    results.append((self.entities[target_id], self.relationships[key]))

        if direction in ("incoming", "both"):
            for source_id, _, key, data in self.graph.in_edges(entity_id, keys=True, data=True):
                if relation_type and data.get("relation_type") != relation_type:
                    continue
                if source_id in self.entities and key in self.relationships:
                    results.append((self.entities[source_id], self.relationships[key]))

        return results

    def find_attack_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 10
    ) -> List[List[str]]:
        """
        Find all attack paths between two entities.

        Args:
            source_id: Starting entity ID
            target_id: Target entity ID
            max_depth: Maximum path length

        Returns:
            List of paths (each path is a list of entity IDs)
        """
        try:
            paths = list(nx.all_simple_paths(
                self.graph,
                source_id,
                target_id,
                cutoff=max_depth
            ))
            return paths
        except nx.NetworkXError:
            return []

    def get_vulnerabilities_for_host(self, host_id: str) -> List[Entity]:
        """Get all vulnerabilities associated with a host."""
        vulns = []

        # Direct vulnerabilities
        related = self.get_related_entities(
            host_id,
            RelationType.HAS_VULNERABILITY,
            direction="outgoing"
        )
        vulns.extend([entity for entity, _ in related])

        # Vulnerabilities through services
        services = self.get_related_entities(
            host_id,
            RelationType.HOSTS,
            direction="outgoing"
        )

        for service, _ in services:
            service_vulns = self.get_related_entities(
                service.id,
                RelationType.HAS_VULNERABILITY,
                direction="outgoing"
            )
            vulns.extend([entity for entity, _ in service_vulns])

        return vulns

    def query_temporal(
        self,
        entity_type: Optional[EntityType] = None,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None
    ) -> List[Entity]:
        """
        Query entities within a time range.

        Args:
            entity_type: Filter by entity type (optional)
            from_time: Start of time range
            to_time: End of time range

        Returns:
            List of matching entities
        """
        results = []

        entities = (
            self.get_entities_by_type(entity_type)
            if entity_type
            else list(self.entities.values())
        )

        for entity in entities:
            # Check temporal validity
            if from_time and entity.created_at < from_time:
                continue
            if to_time and entity.created_at > to_time:
                continue
            if entity.valid_until and from_time and entity.valid_until < from_time:
                continue

            results.append(entity)

        return results

    def get_episodes_for_entity(self, entity_id: str) -> List[Episode]:
        """Get all episodes where an entity was involved."""
        entity = self.entities.get(entity_id)
        if not entity:
            return []

        return [
            self.episodes[ep_id]
            for ep_id in entity.episode_ids
            if ep_id in self.episodes
        ]

    def search_entities(
        self,
        query: str,
        entity_type: Optional[EntityType] = None,
        limit: int = 10
    ) -> List[Entity]:
        """
        Search entities by name or attributes.

        Args:
            query: Search query string
            entity_type: Filter by entity type (optional)
            limit: Maximum results to return

        Returns:
            List of matching entities
        """
        query_lower = query.lower()
        results = []

        entities = (
            self.get_entities_by_type(entity_type)
            if entity_type
            else list(self.entities.values())
        )

        for entity in entities:
            score = 0

            # Check name match
            if query_lower in entity.name.lower():
                score += 10

            # Check attribute matches
            for key, value in entity.attributes.items():
                if isinstance(value, str) and query_lower in value.lower():
                    score += 5

            if score > 0:
                results.append((score, entity))

        # Sort by score and return top results
        results.sort(key=lambda x: x[0], reverse=True)
        return [entity for _, entity in results[:limit]]

    def get_graph_statistics(self) -> Dict[str, Any]:
        """Get statistics about the knowledge graph."""
        return {
            "total_entities": len(self.entities),
            "total_relationships": len(self.relationships),
            "total_episodes": len(self.episodes),
            "entities_by_type": {
                et.value: len(ids) for et, ids in self.entity_type_index.items()
            },
            "graph_density": nx.density(self.graph) if self.graph.number_of_nodes() > 0 else 0,
            "connected_components": (
                nx.number_weakly_connected_components(self.graph)
                if self.graph.number_of_nodes() > 0
                else 0
            )
        }

    def export_to_json(self) -> str:
        """Export the knowledge graph to JSON."""
        data = {
            "entities": [e.model_dump() for e in self.entities.values()],
            "relationships": [r.model_dump() for r in self.relationships.values()],
            "episodes": [ep.model_dump() for ep in self.episodes.values()]
        }
        return json.dumps(data, default=str, indent=2)

    def import_from_json(self, json_str: str):
        """Import knowledge graph from JSON."""
        data = json.loads(json_str)

        for entity_data in data.get("entities", []):
            entity = Entity(**entity_data)
            self.add_entity(entity)

        for rel_data in data.get("relationships", []):
            relationship = Relationship(**rel_data)
            self.add_relationship(relationship)

        for ep_data in data.get("episodes", []):
            episode = Episode(**ep_data)
            self.add_episode(episode)

    def clear(self):
        """Clear all data from the knowledge graph."""
        self.graph.clear()
        self.entities.clear()
        self.relationships.clear()
        self.episodes.clear()
        self.entity_type_index = {et: set() for et in EntityType}
        self.session_index.clear()
        logger.info("Knowledge graph cleared")
