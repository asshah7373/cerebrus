"""
Graphiti-Inspired Bi-Temporal Knowledge Graph

Implements the Graphiti architecture with:
- Bi-temporal data model (event time + ingestion time)
- Episode system for organizing interactions
- Hybrid retrieval (semantic + keyword BM25 + graph traversal)
- Entity-relationship graph structure
- Point-in-time queries
- Temporal versioning

Reference: https://github.com/getzep/graphiti
"""

import asyncio
import hashlib
import heapq
import json
import math
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from pydantic import BaseModel, Field


# =============================================================================
# TEMPORAL TYPES
# =============================================================================

@dataclass
class BiTemporalTimestamp:
    """
    Bi-temporal timestamp tracking both event time and ingestion time.

    - event_time: When the event actually occurred in the real world
    - ingestion_time: When the event was recorded in the system
    """
    event_time: datetime
    ingestion_time: datetime = field(default_factory=datetime.utcnow)

    def __post_init__(self):
        if self.ingestion_time is None:
            self.ingestion_time = datetime.utcnow()

    def to_dict(self) -> Dict[str, str]:
        return {
            "event_time": self.event_time.isoformat(),
            "ingestion_time": self.ingestion_time.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "BiTemporalTimestamp":
        return cls(
            event_time=datetime.fromisoformat(data["event_time"]),
            ingestion_time=datetime.fromisoformat(data["ingestion_time"])
        )

    @classmethod
    def now(cls) -> "BiTemporalTimestamp":
        now = datetime.utcnow()
        return cls(event_time=now, ingestion_time=now)


class EntityType(str, Enum):
    """Types of entities in the security knowledge graph."""
    HOST = "host"
    SERVICE = "service"
    PORT = "port"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    TECHNOLOGY = "technology"
    FINDING = "finding"
    SESSION = "session"
    USER = "user"
    FILE = "file"
    NETWORK = "network"


class RelationType(str, Enum):
    """Types of relationships between entities."""
    HOSTS = "hosts"                    # Host -> Service
    EXPOSES = "exposes"                # Host -> Port
    RUNS_ON = "runs_on"                # Service -> Port
    HAS_VULNERABILITY = "has_vulnerability"  # Entity -> Vulnerability
    USES_TECHNOLOGY = "uses_technology"      # Endpoint -> Technology
    ACCEPTS_PARAMETER = "accepts_parameter"  # Endpoint -> Parameter
    LEADS_TO = "leads_to"              # Finding -> Finding (attack chains)
    DISCOVERED_BY = "discovered_by"    # Finding -> Session
    AUTHENTICATES = "authenticates"    # Credential -> Service
    CONNECTS_TO = "connects_to"        # Host -> Host
    CONTAINS = "contains"              # Network -> Host
    EXPLOITS = "exploits"              # Finding -> Vulnerability
    CHILD_OF = "child_of"              # Endpoint -> Endpoint


# =============================================================================
# GRAPH ENTITIES
# =============================================================================

@dataclass
class GraphEntity:
    """
    An entity in the knowledge graph with bi-temporal tracking.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    entity_type: EntityType = EntityType.HOST
    name: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)

    # Bi-temporal timestamps
    valid_from: BiTemporalTimestamp = field(default_factory=BiTemporalTimestamp.now)
    valid_to: Optional[BiTemporalTimestamp] = None  # None = currently valid

    # Versioning
    version: int = 1
    previous_version_id: Optional[str] = None

    # Embedding for semantic search
    embedding: Optional[List[float]] = None

    # Metadata
    source: str = ""  # Where this entity came from
    confidence: float = 1.0  # Confidence in the entity's existence
    tags: List[str] = field(default_factory=list)

    def is_valid_at(self, timestamp: datetime) -> bool:
        """Check if entity is valid at a specific point in time."""
        if self.valid_from.event_time > timestamp:
            return False
        if self.valid_to and self.valid_to.event_time <= timestamp:
            return False
        return True

    def to_text(self) -> str:
        """Convert entity to text for embedding."""
        parts = [
            f"Type: {self.entity_type.value}",
            f"Name: {self.name}"
        ]
        for key, value in self.properties.items():
            parts.append(f"{key}: {value}")
        return " | ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "entity_type": self.entity_type.value,
            "name": self.name,
            "properties": self.properties,
            "valid_from": self.valid_from.to_dict(),
            "valid_to": self.valid_to.to_dict() if self.valid_to else None,
            "version": self.version,
            "previous_version_id": self.previous_version_id,
            "source": self.source,
            "confidence": self.confidence,
            "tags": self.tags
        }


@dataclass
class GraphRelation:
    """
    A relationship between entities with bi-temporal tracking.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source_id: str = ""
    target_id: str = ""
    relation_type: RelationType = RelationType.CONNECTS_TO
    properties: Dict[str, Any] = field(default_factory=dict)

    # Bi-temporal timestamps
    valid_from: BiTemporalTimestamp = field(default_factory=BiTemporalTimestamp.now)
    valid_to: Optional[BiTemporalTimestamp] = None

    # Metadata
    weight: float = 1.0  # Relationship strength
    confidence: float = 1.0
    source: str = ""

    def is_valid_at(self, timestamp: datetime) -> bool:
        """Check if relationship is valid at a specific point in time."""
        if self.valid_from.event_time > timestamp:
            return False
        if self.valid_to and self.valid_to.event_time <= timestamp:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type.value,
            "properties": self.properties,
            "valid_from": self.valid_from.to_dict(),
            "valid_to": self.valid_to.to_dict() if self.valid_to else None,
            "weight": self.weight,
            "confidence": self.confidence,
            "source": self.source
        }


# =============================================================================
# EPISODE SYSTEM
# =============================================================================

class EpisodeType(str, Enum):
    """Types of episodes."""
    RECONNAISSANCE = "reconnaissance"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"
    USER_INTERACTION = "user_interaction"


@dataclass
class Episode:
    """
    A discrete unit of interaction or activity.

    Episodes group related entities and relationships together,
    providing context for when and how information was discovered.
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    episode_type: EpisodeType = EpisodeType.USER_INTERACTION
    name: str = ""
    description: str = ""

    # Temporal bounds
    started_at: BiTemporalTimestamp = field(default_factory=BiTemporalTimestamp.now)
    ended_at: Optional[BiTemporalTimestamp] = None

    # Content
    entity_ids: List[str] = field(default_factory=list)
    relation_ids: List[str] = field(default_factory=list)

    # Context
    session_id: Optional[str] = None
    target: str = ""
    agent: str = ""

    # Summary
    summary: str = ""
    findings_count: int = 0
    success: bool = True

    def add_entity(self, entity_id: str):
        """Add an entity to this episode."""
        if entity_id not in self.entity_ids:
            self.entity_ids.append(entity_id)

    def add_relation(self, relation_id: str):
        """Add a relationship to this episode."""
        if relation_id not in self.relation_ids:
            self.relation_ids.append(relation_id)

    def close(self, summary: str = ""):
        """Close the episode."""
        self.ended_at = BiTemporalTimestamp.now()
        if summary:
            self.summary = summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "episode_type": self.episode_type.value,
            "name": self.name,
            "description": self.description,
            "started_at": self.started_at.to_dict(),
            "ended_at": self.ended_at.to_dict() if self.ended_at else None,
            "entity_ids": self.entity_ids,
            "relation_ids": self.relation_ids,
            "session_id": self.session_id,
            "target": self.target,
            "agent": self.agent,
            "summary": self.summary,
            "findings_count": self.findings_count,
            "success": self.success
        }


# =============================================================================
# BM25 KEYWORD SEARCH
# =============================================================================

class BM25Index:
    """
    BM25 index for keyword-based retrieval.

    Implements the Okapi BM25 ranking function for efficient
    keyword search across entity text representations.
    """

    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.documents: Dict[str, str] = {}  # doc_id -> text
        self.doc_lengths: Dict[str, int] = {}
        self.avg_doc_length: float = 0.0
        self.term_frequencies: Dict[str, Dict[str, int]] = {}  # term -> {doc_id: freq}
        self.doc_frequencies: Dict[str, int] = {}  # term -> num_docs_containing
        self.total_docs: int = 0

    def add_document(self, doc_id: str, text: str):
        """Add a document to the index."""
        # Tokenize
        tokens = self._tokenize(text)

        self.documents[doc_id] = text
        self.doc_lengths[doc_id] = len(tokens)
        self.total_docs += 1

        # Update average document length
        self.avg_doc_length = sum(self.doc_lengths.values()) / self.total_docs

        # Update term frequencies
        term_counts = defaultdict(int)
        for token in tokens:
            term_counts[token] += 1

        for term, count in term_counts.items():
            if term not in self.term_frequencies:
                self.term_frequencies[term] = {}
            self.term_frequencies[term][doc_id] = count

            # Update document frequency
            if term not in self.doc_frequencies:
                self.doc_frequencies[term] = 0
            self.doc_frequencies[term] += 1

    def remove_document(self, doc_id: str):
        """Remove a document from the index."""
        if doc_id not in self.documents:
            return

        text = self.documents[doc_id]
        tokens = self._tokenize(text)
        term_counts = defaultdict(int)
        for token in tokens:
            term_counts[token] += 1

        # Update term frequencies
        for term, count in term_counts.items():
            if term in self.term_frequencies:
                if doc_id in self.term_frequencies[term]:
                    del self.term_frequencies[term][doc_id]
                    self.doc_frequencies[term] -= 1

        del self.documents[doc_id]
        del self.doc_lengths[doc_id]
        self.total_docs -= 1

        if self.total_docs > 0:
            self.avg_doc_length = sum(self.doc_lengths.values()) / self.total_docs
        else:
            self.avg_doc_length = 0.0

    def search(self, query: str, top_k: int = 10) -> List[Tuple[str, float]]:
        """Search for documents matching the query."""
        query_tokens = self._tokenize(query)
        scores: Dict[str, float] = defaultdict(float)

        for term in query_tokens:
            if term not in self.term_frequencies:
                continue

            # IDF calculation
            df = self.doc_frequencies.get(term, 0)
            if df == 0:
                continue
            idf = math.log((self.total_docs - df + 0.5) / (df + 0.5) + 1)

            # Score each document containing this term
            for doc_id, tf in self.term_frequencies[term].items():
                doc_len = self.doc_lengths[doc_id]
                numerator = tf * (self.k1 + 1)
                denominator = tf + self.k1 * (
                    1 - self.b + self.b * (doc_len / self.avg_doc_length)
                )
                scores[doc_id] += idf * (numerator / denominator)

        # Return top k results
        results = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into terms."""
        # Lowercase and split on non-alphanumeric
        text = text.lower()
        tokens = re.findall(r'\b[a-z0-9]+\b', text)
        return tokens


# =============================================================================
# GRAPHITI KNOWLEDGE GRAPH
# =============================================================================

class GraphitiKnowledgeGraph:
    """
    Graphiti-inspired bi-temporal knowledge graph.

    Features:
    - Bi-temporal data model for all entities and relationships
    - Episode system for organizing interactions
    - Hybrid retrieval (semantic + BM25 keyword + graph traversal)
    - Point-in-time queries
    - Entity versioning
    """

    def __init__(
        self,
        embedding_function: Optional[Callable[[str], List[float]]] = None
    ):
        # Entity and relationship storage
        self.entities: Dict[str, GraphEntity] = {}
        self.relations: Dict[str, GraphRelation] = {}
        self.episodes: Dict[str, Episode] = {}

        # Indexes
        self.entity_by_type: Dict[EntityType, Set[str]] = defaultdict(set)
        self.entity_by_name: Dict[str, Set[str]] = defaultdict(set)
        self.relations_from: Dict[str, Set[str]] = defaultdict(set)  # source_id -> relation_ids
        self.relations_to: Dict[str, Set[str]] = defaultdict(set)    # target_id -> relation_ids
        self.entity_versions: Dict[str, List[str]] = defaultdict(list)  # base_name -> version_ids

        # Search indexes
        self.bm25_index = BM25Index()
        self.embedding_function = embedding_function

        # Current episode
        self.current_episode: Optional[Episode] = None

    # =========================================================================
    # EPISODE MANAGEMENT
    # =========================================================================

    def start_episode(
        self,
        episode_type: EpisodeType,
        name: str,
        description: str = "",
        session_id: str = None,
        target: str = "",
        agent: str = ""
    ) -> Episode:
        """Start a new episode."""
        # Close any existing episode
        if self.current_episode:
            self.close_episode()

        episode = Episode(
            episode_type=episode_type,
            name=name,
            description=description,
            session_id=session_id,
            target=target,
            agent=agent
        )

        self.episodes[episode.id] = episode
        self.current_episode = episode

        return episode

    def close_episode(self, summary: str = "") -> Optional[Episode]:
        """Close the current episode."""
        if not self.current_episode:
            return None

        self.current_episode.close(summary)
        episode = self.current_episode
        self.current_episode = None

        return episode

    def get_episode(self, episode_id: str) -> Optional[Episode]:
        """Get an episode by ID."""
        return self.episodes.get(episode_id)

    def get_episodes_in_range(
        self,
        start: datetime,
        end: datetime,
        episode_type: Optional[EpisodeType] = None
    ) -> List[Episode]:
        """Get episodes within a time range."""
        results = []

        for episode in self.episodes.values():
            # Check time range
            ep_start = episode.started_at.event_time
            ep_end = episode.ended_at.event_time if episode.ended_at else datetime.utcnow()

            if ep_start <= end and ep_end >= start:
                if episode_type is None or episode.episode_type == episode_type:
                    results.append(episode)

        return sorted(results, key=lambda e: e.started_at.event_time)

    # =========================================================================
    # ENTITY MANAGEMENT
    # =========================================================================

    def add_entity(
        self,
        entity_type: EntityType,
        name: str,
        properties: Dict[str, Any] = None,
        event_time: datetime = None,
        source: str = "",
        confidence: float = 1.0,
        tags: List[str] = None
    ) -> GraphEntity:
        """Add a new entity to the graph."""
        # Create bi-temporal timestamp
        timestamp = BiTemporalTimestamp(
            event_time=event_time or datetime.utcnow(),
            ingestion_time=datetime.utcnow()
        )

        entity = GraphEntity(
            entity_type=entity_type,
            name=name,
            properties=properties or {},
            valid_from=timestamp,
            source=source,
            confidence=confidence,
            tags=tags or []
        )

        # Generate embedding
        if self.embedding_function:
            entity.embedding = self.embedding_function(entity.to_text())

        # Store entity
        self.entities[entity.id] = entity

        # Update indexes
        self.entity_by_type[entity_type].add(entity.id)
        self.entity_by_name[name.lower()].add(entity.id)
        self.entity_versions[name.lower()].append(entity.id)

        # Add to BM25 index
        self.bm25_index.add_document(entity.id, entity.to_text())

        # Add to current episode
        if self.current_episode:
            self.current_episode.add_entity(entity.id)

        return entity

    def update_entity(
        self,
        entity_id: str,
        properties: Dict[str, Any] = None,
        event_time: datetime = None
    ) -> Optional[GraphEntity]:
        """
        Update an entity, creating a new version.

        The old version is invalidated (valid_to set) and a new version is created.
        """
        old_entity = self.entities.get(entity_id)
        if not old_entity:
            return None

        # Invalidate old version
        now = BiTemporalTimestamp(
            event_time=event_time or datetime.utcnow(),
            ingestion_time=datetime.utcnow()
        )
        old_entity.valid_to = now

        # Create new version
        new_entity = GraphEntity(
            entity_type=old_entity.entity_type,
            name=old_entity.name,
            properties={**old_entity.properties, **(properties or {})},
            valid_from=now,
            version=old_entity.version + 1,
            previous_version_id=old_entity.id,
            source=old_entity.source,
            confidence=old_entity.confidence,
            tags=old_entity.tags.copy()
        )

        # Generate new embedding
        if self.embedding_function:
            new_entity.embedding = self.embedding_function(new_entity.to_text())

        # Store new version
        self.entities[new_entity.id] = new_entity

        # Update indexes
        self.entity_by_type[new_entity.entity_type].add(new_entity.id)
        self.entity_by_name[new_entity.name.lower()].add(new_entity.id)
        self.entity_versions[new_entity.name.lower()].append(new_entity.id)

        # Update BM25 index
        self.bm25_index.remove_document(old_entity.id)
        self.bm25_index.add_document(new_entity.id, new_entity.to_text())

        # Add to current episode
        if self.current_episode:
            self.current_episode.add_entity(new_entity.id)

        return new_entity

    def get_entity(self, entity_id: str) -> Optional[GraphEntity]:
        """Get an entity by ID."""
        return self.entities.get(entity_id)

    def get_entity_at_time(
        self,
        name: str,
        timestamp: datetime
    ) -> Optional[GraphEntity]:
        """Get the version of an entity valid at a specific time."""
        entity_ids = self.entity_by_name.get(name.lower(), set())

        for entity_id in entity_ids:
            entity = self.entities.get(entity_id)
            if entity and entity.is_valid_at(timestamp):
                return entity

        return None

    def get_entity_history(self, name: str) -> List[GraphEntity]:
        """Get all versions of an entity."""
        entity_ids = self.entity_versions.get(name.lower(), [])
        return [
            self.entities[eid] for eid in entity_ids
            if eid in self.entities
        ]

    def get_entities_by_type(
        self,
        entity_type: EntityType,
        valid_at: datetime = None
    ) -> List[GraphEntity]:
        """Get all entities of a specific type."""
        entity_ids = self.entity_by_type.get(entity_type, set())
        entities = []

        for entity_id in entity_ids:
            entity = self.entities.get(entity_id)
            if entity:
                if valid_at is None or entity.is_valid_at(valid_at):
                    entities.append(entity)

        return entities

    def invalidate_entity(
        self,
        entity_id: str,
        event_time: datetime = None
    ) -> bool:
        """Invalidate an entity (set valid_to)."""
        entity = self.entities.get(entity_id)
        if not entity:
            return False

        entity.valid_to = BiTemporalTimestamp(
            event_time=event_time or datetime.utcnow(),
            ingestion_time=datetime.utcnow()
        )

        return True

    # =========================================================================
    # RELATIONSHIP MANAGEMENT
    # =========================================================================

    def add_relation(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        properties: Dict[str, Any] = None,
        event_time: datetime = None,
        weight: float = 1.0,
        confidence: float = 1.0,
        source: str = ""
    ) -> Optional[GraphRelation]:
        """Add a relationship between entities."""
        # Verify entities exist
        if source_id not in self.entities or target_id not in self.entities:
            return None

        timestamp = BiTemporalTimestamp(
            event_time=event_time or datetime.utcnow(),
            ingestion_time=datetime.utcnow()
        )

        relation = GraphRelation(
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            properties=properties or {},
            valid_from=timestamp,
            weight=weight,
            confidence=confidence,
            source=source
        )

        # Store relation
        self.relations[relation.id] = relation

        # Update indexes
        self.relations_from[source_id].add(relation.id)
        self.relations_to[target_id].add(relation.id)

        # Add to current episode
        if self.current_episode:
            self.current_episode.add_relation(relation.id)

        return relation

    def get_relation(self, relation_id: str) -> Optional[GraphRelation]:
        """Get a relationship by ID."""
        return self.relations.get(relation_id)

    def get_relations_from(
        self,
        entity_id: str,
        relation_type: RelationType = None,
        valid_at: datetime = None
    ) -> List[GraphRelation]:
        """Get all relations originating from an entity."""
        relation_ids = self.relations_from.get(entity_id, set())
        relations = []

        for rel_id in relation_ids:
            relation = self.relations.get(rel_id)
            if relation:
                if relation_type and relation.relation_type != relation_type:
                    continue
                if valid_at and not relation.is_valid_at(valid_at):
                    continue
                relations.append(relation)

        return relations

    def get_relations_to(
        self,
        entity_id: str,
        relation_type: RelationType = None,
        valid_at: datetime = None
    ) -> List[GraphRelation]:
        """Get all relations pointing to an entity."""
        relation_ids = self.relations_to.get(entity_id, set())
        relations = []

        for rel_id in relation_ids:
            relation = self.relations.get(rel_id)
            if relation:
                if relation_type and relation.relation_type != relation_type:
                    continue
                if valid_at and not relation.is_valid_at(valid_at):
                    continue
                relations.append(relation)

        return relations

    def get_neighbors(
        self,
        entity_id: str,
        direction: str = "both",
        relation_type: RelationType = None,
        valid_at: datetime = None
    ) -> List[GraphEntity]:
        """Get neighboring entities."""
        neighbors = []
        seen = set()

        if direction in ("out", "both"):
            for relation in self.get_relations_from(entity_id, relation_type, valid_at):
                if relation.target_id not in seen:
                    entity = self.entities.get(relation.target_id)
                    if entity and (valid_at is None or entity.is_valid_at(valid_at)):
                        neighbors.append(entity)
                        seen.add(relation.target_id)

        if direction in ("in", "both"):
            for relation in self.get_relations_to(entity_id, relation_type, valid_at):
                if relation.source_id not in seen:
                    entity = self.entities.get(relation.source_id)
                    if entity and (valid_at is None or entity.is_valid_at(valid_at)):
                        neighbors.append(entity)
                        seen.add(relation.source_id)

        return neighbors

    # =========================================================================
    # HYBRID RETRIEVAL
    # =========================================================================

    def search(
        self,
        query: str,
        entity_types: List[EntityType] = None,
        valid_at: datetime = None,
        top_k: int = 10,
        use_semantic: bool = True,
        use_keyword: bool = True,
        use_graph: bool = True,
        semantic_weight: float = 0.4,
        keyword_weight: float = 0.3,
        graph_weight: float = 0.3
    ) -> List[Tuple[GraphEntity, float]]:
        """
        Hybrid search combining semantic, keyword (BM25), and graph traversal.

        Returns entities ranked by combined score.
        """
        scores: Dict[str, float] = defaultdict(float)

        # Semantic search
        if use_semantic and self.embedding_function:
            semantic_results = self._semantic_search(query, top_k * 2)
            max_sem = max((s for _, s in semantic_results), default=1.0) or 1.0
            for entity_id, score in semantic_results:
                scores[entity_id] += semantic_weight * (score / max_sem)

        # Keyword search (BM25)
        if use_keyword:
            keyword_results = self.bm25_index.search(query, top_k * 2)
            max_kw = max((s for _, s in keyword_results), default=1.0) or 1.0
            for entity_id, score in keyword_results:
                scores[entity_id] += keyword_weight * (score / max_kw)

        # Graph-based scoring (boost entities with more connections)
        if use_graph:
            for entity_id in scores.keys():
                graph_score = self._compute_graph_score(entity_id)
                scores[entity_id] += graph_weight * graph_score

        # Filter and rank results
        results = []
        for entity_id, score in scores.items():
            entity = self.entities.get(entity_id)
            if not entity:
                continue

            # Apply filters
            if entity_types and entity.entity_type not in entity_types:
                continue
            if valid_at and not entity.is_valid_at(valid_at):
                continue

            results.append((entity, score))

        # Sort by score
        results.sort(key=lambda x: x[1], reverse=True)

        return results[:top_k]

    def _semantic_search(
        self,
        query: str,
        top_k: int
    ) -> List[Tuple[str, float]]:
        """Perform semantic search using embeddings."""
        if not self.embedding_function:
            return []

        query_embedding = self.embedding_function(query)
        results = []

        for entity_id, entity in self.entities.items():
            if entity.embedding:
                similarity = self._cosine_similarity(
                    query_embedding,
                    entity.embedding
                )
                results.append((entity_id, similarity))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def _compute_graph_score(self, entity_id: str) -> float:
        """Compute graph-based importance score."""
        # PageRank-like scoring based on incoming connections
        in_relations = len(self.relations_to.get(entity_id, set()))
        out_relations = len(self.relations_from.get(entity_id, set()))

        # Normalize score
        total_relations = in_relations + out_relations
        if total_relations == 0:
            return 0.0

        # Weight incoming relations more heavily
        score = (in_relations * 2 + out_relations) / (total_relations * 3)
        return min(score, 1.0)

    @staticmethod
    def _cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between two vectors."""
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = sum(a * a for a in vec1) ** 0.5
        norm2 = sum(b * b for b in vec2) ** 0.5
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot_product / (norm1 * norm2)

    # =========================================================================
    # GRAPH TRAVERSAL
    # =========================================================================

    def find_path(
        self,
        start_id: str,
        end_id: str,
        max_depth: int = 5,
        valid_at: datetime = None
    ) -> Optional[List[str]]:
        """Find shortest path between two entities using BFS."""
        if start_id not in self.entities or end_id not in self.entities:
            return None

        visited = {start_id}
        queue = [(start_id, [start_id])]

        while queue:
            current_id, path = queue.pop(0)

            if len(path) > max_depth:
                continue

            if current_id == end_id:
                return path

            # Explore neighbors
            neighbors = self.get_neighbors(current_id, direction="out", valid_at=valid_at)
            for neighbor in neighbors:
                if neighbor.id not in visited:
                    visited.add(neighbor.id)
                    queue.append((neighbor.id, path + [neighbor.id]))

        return None

    def find_attack_chains(
        self,
        start_entity_id: str,
        max_depth: int = 5,
        valid_at: datetime = None
    ) -> List[List[GraphEntity]]:
        """
        Find potential attack chains starting from an entity.

        Follows LEADS_TO and EXPLOITS relationships.
        """
        chains = []
        attack_relations = {RelationType.LEADS_TO, RelationType.EXPLOITS}

        def dfs(
            current_id: str,
            current_chain: List[str],
            visited: Set[str]
        ):
            if len(current_chain) > max_depth:
                return

            # Get relevant outgoing relations
            relations = self.get_relations_from(current_id, valid_at=valid_at)
            attack_rels = [r for r in relations if r.relation_type in attack_relations]

            if not attack_rels and len(current_chain) > 1:
                # End of chain - add to results
                chains.append(current_chain.copy())
                return

            for relation in attack_rels:
                if relation.target_id not in visited:
                    visited.add(relation.target_id)
                    current_chain.append(relation.target_id)
                    dfs(relation.target_id, current_chain, visited)
                    current_chain.pop()
                    visited.remove(relation.target_id)

        dfs(start_entity_id, [start_entity_id], {start_entity_id})

        # Convert IDs to entities
        return [
            [self.entities[eid] for eid in chain if eid in self.entities]
            for chain in chains
        ]

    def get_subgraph(
        self,
        center_entity_id: str,
        depth: int = 2,
        valid_at: datetime = None
    ) -> Tuple[List[GraphEntity], List[GraphRelation]]:
        """Extract a subgraph centered on an entity."""
        entities = set()
        relations = set()

        def expand(entity_id: str, current_depth: int):
            if current_depth > depth:
                return
            if entity_id in entities:
                return

            entity = self.entities.get(entity_id)
            if not entity:
                return
            if valid_at and not entity.is_valid_at(valid_at):
                return

            entities.add(entity_id)

            # Get relations
            for rel in self.get_relations_from(entity_id, valid_at=valid_at):
                relations.add(rel.id)
                expand(rel.target_id, current_depth + 1)

            for rel in self.get_relations_to(entity_id, valid_at=valid_at):
                relations.add(rel.id)
                expand(rel.source_id, current_depth + 1)

        expand(center_entity_id, 0)

        entity_list = [self.entities[eid] for eid in entities]
        relation_list = [self.relations[rid] for rid in relations]

        return entity_list, relation_list

    # =========================================================================
    # POINT-IN-TIME QUERIES
    # =========================================================================

    def get_graph_at_time(
        self,
        timestamp: datetime
    ) -> Tuple[List[GraphEntity], List[GraphRelation]]:
        """Get the complete graph state at a specific point in time."""
        valid_entities = [
            entity for entity in self.entities.values()
            if entity.is_valid_at(timestamp)
        ]

        valid_relations = [
            relation for relation in self.relations.values()
            if relation.is_valid_at(timestamp)
        ]

        return valid_entities, valid_relations

    def get_changes_in_range(
        self,
        start: datetime,
        end: datetime
    ) -> Dict[str, List[Union[GraphEntity, GraphRelation]]]:
        """Get all changes (additions, modifications, deletions) in a time range."""
        changes = {
            "added_entities": [],
            "modified_entities": [],
            "removed_entities": [],
            "added_relations": [],
            "removed_relations": []
        }

        for entity in self.entities.values():
            created = entity.valid_from.event_time
            if start <= created <= end:
                if entity.previous_version_id:
                    changes["modified_entities"].append(entity)
                else:
                    changes["added_entities"].append(entity)

            if entity.valid_to:
                removed = entity.valid_to.event_time
                if start <= removed <= end:
                    changes["removed_entities"].append(entity)

        for relation in self.relations.values():
            created = relation.valid_from.event_time
            if start <= created <= end:
                changes["added_relations"].append(relation)

            if relation.valid_to:
                removed = relation.valid_to.event_time
                if start <= removed <= end:
                    changes["removed_relations"].append(relation)

        return changes

    # =========================================================================
    # SECURITY-SPECIFIC QUERIES
    # =========================================================================

    def get_vulnerabilities_for_host(
        self,
        host_id: str,
        valid_at: datetime = None
    ) -> List[GraphEntity]:
        """Get all vulnerabilities associated with a host."""
        vulnerabilities = []

        # Direct vulnerabilities
        relations = self.get_relations_from(
            host_id,
            relation_type=RelationType.HAS_VULNERABILITY,
            valid_at=valid_at
        )

        for rel in relations:
            vuln = self.entities.get(rel.target_id)
            if vuln and vuln.entity_type == EntityType.VULNERABILITY:
                vulnerabilities.append(vuln)

        # Vulnerabilities through services
        service_relations = self.get_relations_from(
            host_id,
            relation_type=RelationType.HOSTS,
            valid_at=valid_at
        )

        for service_rel in service_relations:
            service_vulns = self.get_relations_from(
                service_rel.target_id,
                relation_type=RelationType.HAS_VULNERABILITY,
                valid_at=valid_at
            )
            for vuln_rel in service_vulns:
                vuln = self.entities.get(vuln_rel.target_id)
                if vuln and vuln.entity_type == EntityType.VULNERABILITY:
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def get_services_by_port(
        self,
        port: int,
        valid_at: datetime = None
    ) -> List[GraphEntity]:
        """Find all services running on a specific port."""
        services = []

        port_entities = self.get_entities_by_type(EntityType.PORT, valid_at)

        for port_entity in port_entities:
            if port_entity.properties.get("number") == port:
                # Find services on this port
                relations = self.get_relations_to(
                    port_entity.id,
                    relation_type=RelationType.RUNS_ON,
                    valid_at=valid_at
                )
                for rel in relations:
                    service = self.entities.get(rel.source_id)
                    if service:
                        services.append(service)

        return services

    def get_credential_coverage(
        self,
        valid_at: datetime = None
    ) -> Dict[str, Any]:
        """Get credential coverage analysis."""
        credentials = self.get_entities_by_type(EntityType.CREDENTIAL, valid_at)
        services = self.get_entities_by_type(EntityType.SERVICE, valid_at)

        authenticated_services = set()
        for cred in credentials:
            relations = self.get_relations_from(
                cred.id,
                relation_type=RelationType.AUTHENTICATES,
                valid_at=valid_at
            )
            for rel in relations:
                authenticated_services.add(rel.target_id)

        return {
            "total_credentials": len(credentials),
            "total_services": len(services),
            "authenticated_services": len(authenticated_services),
            "coverage_percentage": (
                len(authenticated_services) / len(services) * 100
                if services else 0
            )
        }

    # =========================================================================
    # EXPORT AND SERIALIZATION
    # =========================================================================

    def export_to_dict(self) -> Dict[str, Any]:
        """Export the entire graph to a dictionary."""
        return {
            "entities": [e.to_dict() for e in self.entities.values()],
            "relations": [r.to_dict() for r in self.relations.values()],
            "episodes": [ep.to_dict() for ep in self.episodes.values()]
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get graph statistics."""
        entity_counts = defaultdict(int)
        for entity in self.entities.values():
            entity_counts[entity.entity_type.value] += 1

        relation_counts = defaultdict(int)
        for relation in self.relations.values():
            relation_counts[relation.relation_type.value] += 1

        return {
            "total_entities": len(self.entities),
            "total_relations": len(self.relations),
            "total_episodes": len(self.episodes),
            "entities_by_type": dict(entity_counts),
            "relations_by_type": dict(relation_counts),
            "current_episode": self.current_episode.id if self.current_episode else None
        }


# =============================================================================
# SECURITY KNOWLEDGE GRAPH BUILDER
# =============================================================================

class SecurityKnowledgeGraphBuilder:
    """
    Helper class for building security-focused knowledge graphs.

    Provides convenient methods for adding common security entities
    and relationships.
    """

    def __init__(self, graph: GraphitiKnowledgeGraph):
        self.graph = graph

    def add_host(
        self,
        ip: str,
        hostname: str = None,
        os: str = None,
        source: str = "discovery"
    ) -> GraphEntity:
        """Add a host entity."""
        properties = {"ip": ip}
        if hostname:
            properties["hostname"] = hostname
        if os:
            properties["os"] = os

        return self.graph.add_entity(
            entity_type=EntityType.HOST,
            name=ip,
            properties=properties,
            source=source,
            tags=["host", "infrastructure"]
        )

    def add_service(
        self,
        name: str,
        version: str = None,
        host_id: str = None,
        port: int = None,
        protocol: str = "tcp",
        source: str = "discovery"
    ) -> Tuple[GraphEntity, Optional[GraphRelation]]:
        """Add a service entity and optionally link to host."""
        properties = {
            "name": name,
            "protocol": protocol
        }
        if version:
            properties["version"] = version
        if port:
            properties["port"] = port

        service = self.graph.add_entity(
            entity_type=EntityType.SERVICE,
            name=f"{name}:{port}" if port else name,
            properties=properties,
            source=source,
            tags=["service"]
        )

        relation = None
        if host_id:
            relation = self.graph.add_relation(
                source_id=host_id,
                target_id=service.id,
                relation_type=RelationType.HOSTS,
                source=source
            )

        return service, relation

    def add_vulnerability(
        self,
        name: str,
        severity: str,
        cve: str = None,
        cvss: float = None,
        description: str = None,
        affected_entity_id: str = None,
        source: str = "scanning"
    ) -> Tuple[GraphEntity, Optional[GraphRelation]]:
        """Add a vulnerability entity."""
        properties = {
            "severity": severity,
            "description": description or ""
        }
        if cve:
            properties["cve"] = cve
        if cvss is not None:
            properties["cvss"] = cvss

        vuln = self.graph.add_entity(
            entity_type=EntityType.VULNERABILITY,
            name=name,
            properties=properties,
            source=source,
            tags=["vulnerability", severity.lower()]
        )

        relation = None
        if affected_entity_id:
            relation = self.graph.add_relation(
                source_id=affected_entity_id,
                target_id=vuln.id,
                relation_type=RelationType.HAS_VULNERABILITY,
                source=source
            )

        return vuln, relation

    def add_finding(
        self,
        title: str,
        finding_type: str,
        severity: str,
        evidence: str,
        target_id: str = None,
        exploits_vuln_id: str = None,
        source: str = "testing"
    ) -> GraphEntity:
        """Add a security finding."""
        properties = {
            "type": finding_type,
            "severity": severity,
            "evidence": evidence,
            "validated": True
        }

        finding = self.graph.add_entity(
            entity_type=EntityType.FINDING,
            name=title,
            properties=properties,
            source=source,
            tags=["finding", severity.lower(), finding_type.lower()]
        )

        if target_id:
            self.graph.add_relation(
                source_id=finding.id,
                target_id=target_id,
                relation_type=RelationType.HAS_VULNERABILITY,
                source=source
            )

        if exploits_vuln_id:
            self.graph.add_relation(
                source_id=finding.id,
                target_id=exploits_vuln_id,
                relation_type=RelationType.EXPLOITS,
                source=source
            )

        return finding

    def add_endpoint(
        self,
        path: str,
        method: str = "GET",
        parameters: List[str] = None,
        host_id: str = None,
        technology: str = None,
        source: str = "discovery"
    ) -> GraphEntity:
        """Add a web endpoint entity."""
        properties = {
            "path": path,
            "method": method,
            "parameters": parameters or []
        }
        if technology:
            properties["technology"] = technology

        endpoint = self.graph.add_entity(
            entity_type=EntityType.ENDPOINT,
            name=f"{method} {path}",
            properties=properties,
            source=source,
            tags=["endpoint", "web"]
        )

        if host_id:
            self.graph.add_relation(
                source_id=host_id,
                target_id=endpoint.id,
                relation_type=RelationType.EXPOSES,
                source=source
            )

        return endpoint

    def link_attack_chain(
        self,
        finding_ids: List[str],
        source: str = "analysis"
    ) -> List[GraphRelation]:
        """Create attack chain relationships between findings."""
        relations = []

        for i in range(len(finding_ids) - 1):
            relation = self.graph.add_relation(
                source_id=finding_ids[i],
                target_id=finding_ids[i + 1],
                relation_type=RelationType.LEADS_TO,
                source=source
            )
            if relation:
                relations.append(relation)

        return relations
