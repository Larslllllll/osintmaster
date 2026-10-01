"""Investigation entities, observations, evidence, and provenance queries."""

from __future__ import annotations

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from osintmaster.graph.canonicalize import canonicalize
from osintmaster.graph.types import EvidenceMethod, ObservationState

if TYPE_CHECKING:
    from osintmaster.core.models import Correlation
    from osintmaster.investigation.models import EdgeType, Event


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return uuid4().hex


def evidence_method(detail_type: str, provider: str) -> str:
    detail = detail_type.lower()
    if provider == "input":
        return EvidenceMethod.USER_INPUT.value
    if "dns" in detail or provider.lower() in {"dns", "reverse dns"}:
        return EvidenceMethod.DNS.value
    if "image" in detail or "exif" in detail:
        return EvidenceMethod.IMAGE_METADATA.value
    if detail.startswith("api_"):
        return EvidenceMethod.PUBLIC_API.value
    if detail.startswith(("profile_", "telegram_")):
        return EvidenceMethod.PUBLIC_HTML.value
    return EvidenceMethod.PUBLIC_METADATA.value


@dataclass
class Entity:
    id: str
    type: str
    value: str
    canonical_value: str
    first_seen: str
    last_seen: str
    attributes: dict[str, Any] = field(default_factory=dict)
    aliases: list[str] = field(default_factory=list)
    state: str = "observed"
    observations: int = 0
    confidence: float | None = None  # Legacy observation strength, never identity probability.

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceRecord:
    id: str
    provider: str
    collected_at: str
    method: str
    source_url: str | None = None
    raw_reference: str | None = None
    content_hash: str | None = None
    excerpt: str | None = None
    reliability: str = "unknown"
    provider_run_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Observation:
    id: str
    entity_id: str
    property: str
    value: Any
    state: str
    observed_at: str
    provider: str
    evidence_ids: list[str] = field(default_factory=list)
    provider_run_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Relation:
    id: str
    source: str
    target: str
    type: str
    provider: str
    created_at: str
    source_url: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    strength: str = "direct"
    score: int | None = None
    features: dict[str, Any] = field(default_factory=dict)
    contradictions: list[dict[str, Any]] = field(default_factory=list)
    provider_run_id: str | None = None
    # Compatibility with existing graph clients.
    confidence: float = 1.0
    evidence: list[dict[str, Any]] = field(default_factory=list)

    @property
    def timestamp(self) -> str:
        return self.created_at

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.created_at
        return result


@dataclass
class ProviderRun:
    id: str
    provider: str
    input_entity_id: str
    started_at: str
    finished_at: str
    status: str
    requests_made: int
    entities_created: int
    observations_created: int
    relations_created: int
    error: str | None = None
    rate_limits: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PivotCandidate:
    entity_id: str
    discovered_from: str | None
    expected_information_gain: float
    cost: float
    priority: float
    reason: str
    status: str = "recommended"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Investigation:
    id: str
    name: str
    created_at: str
    updated_at: str
    seed_entities: list[str] = field(default_factory=list)
    status: str = "running"
    settings: dict[str, Any] = field(default_factory=dict)
    budgets: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


PIVOT_GAIN = {
    "DOMAIN": 0.95,
    "EMAIL": 0.90,
    "IMAGE_HASH": 0.90,
    "USERNAME": 0.85,
    "PHONE": 0.85,
    "IP_ADDRESS": 0.65,
    "URL": 0.40,
    "PERSON_NAME": 0.35,
    "LOCATION": 0.20,
    "PROFILE": 0.15,
}


class InvestigationGraph:
    """Single graph write API; legacy events are input observations."""

    def __init__(
        self,
        investigation_id: str | None = None,
        *,
        name: str = "",
        settings: dict[str, Any] | None = None,
        budgets: dict[str, Any] | None = None,
    ) -> None:
        now = utc_now()
        self.investigation = Investigation(
            investigation_id or new_id(),
            name,
            now,
            now,
            settings=settings or {},
            budgets=budgets or {},
        )
        self.nodes: dict[str, Entity] = {}
        self.edges: list[Relation] = []
        self.observations: list[Observation] = []
        self.evidence: list[EvidenceRecord] = []
        self.provider_runs: list[ProviderRun] = []
        self.pivot_candidates: dict[str, PivotCandidate] = {}
        self._canonical: dict[tuple[str, str, str | None], str] = {}
        self._event_nodes: dict[str, str] = {}
        self._relation_index: dict[tuple[str, str, str, str, str | None], Relation] = {}

    def add_entity(
        self,
        kind: str,
        value: str,
        *,
        observed_at: str | None = None,
        platform: str | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> Entity:
        canonical = canonicalize(kind, value, platform=platform)
        scope = platform.lower() if platform and kind.upper() == "USERNAME" else None
        key = (kind.upper(), canonical, scope)
        timestamp = observed_at or utc_now()
        existing_id = self._canonical.get(key)
        if existing_id:
            entity = self.nodes[existing_id]
            entity.last_seen = max(entity.last_seen, timestamp)
            if value != entity.value and value not in entity.aliases:
                entity.aliases.append(value)
            if attributes:
                entity.attributes.update(attributes)
            return entity
        entity = Entity(
            new_id(), kind.upper(), value, canonical, timestamp, timestamp, attributes or {}
        )
        self.nodes[entity.id] = entity
        self._canonical[key] = entity.id
        self.investigation.updated_at = timestamp
        return entity

    def find_entities(self, kind: str | None = None, value: str | None = None) -> list[Entity]:
        canonical = canonicalize(kind, value) if kind and value is not None else None
        return [
            node
            for node in self.nodes.values()
            if (kind is None or node.type == kind.upper())
            and (
                value is None
                or node.value == value
                or value in node.aliases
                or (canonical is not None and node.canonical_value == canonical)
            )
        ]

    def add_evidence(
        self,
        provider: str,
        *,
        method: str,
        source_url: str | None = None,
        collected_at: str | None = None,
        excerpt: str | None = None,
        raw_reference: str | None = None,
        content_hash: str | None = None,
        reliability: str = "unknown",
        provider_run_id: str | None = None,
    ) -> EvidenceRecord:
        evidence = EvidenceRecord(
            new_id(),
            provider,
            collected_at or utc_now(),
            method,
            source_url,
            raw_reference,
            content_hash,
            excerpt[:500] if excerpt else None,
            reliability,
            provider_run_id,
        )
        self.evidence.append(evidence)
        return evidence

    def add_observation(
        self,
        entity_id: str,
        property: str,
        value: Any,
        *,
        provider: str,
        state: str = "CONFIRMED",
        observed_at: str | None = None,
        evidence_ids: list[str] | None = None,
        provider_run_id: str | None = None,
    ) -> Observation:
        if entity_id not in self.nodes:
            raise KeyError(entity_id)
        if state not in {item.value for item in ObservationState}:
            raise ValueError("Unknown observation state")
        observation = Observation(
            new_id(),
            entity_id,
            property,
            value,
            state,
            observed_at or utc_now(),
            provider,
            evidence_ids or [],
            provider_run_id,
        )
        self.observations.append(observation)
        self.nodes[entity_id].observations += 1
        self.investigation.updated_at = observation.observed_at
        return observation

    def add_relation(
        self,
        source: str,
        target: str,
        relation_type: str,
        *,
        provider: str,
        source_url: str | None = None,
        evidence_ids: list[str] | None = None,
        evidence: list[dict[str, Any]] | None = None,
        strength: str = "direct",
        score: int | None = None,
        features: dict[str, Any] | None = None,
        contradictions: list[dict[str, Any]] | None = None,
        confidence: float = 1.0,
        created_at: str | None = None,
        provider_run_id: str | None = None,
    ) -> Relation | None:
        if source not in self.nodes or target not in self.nodes:
            raise KeyError("Relation endpoint is missing")
        if strength not in {"direct", "derived", "hypothesis"}:
            raise ValueError("Invalid relation strength")
        if score is not None and not 0 <= score <= 100:
            raise ValueError("Evidence score must be from 0 to 100")
        if not 0 <= confidence <= 1:
            raise ValueError("Relation confidence must be from 0 to 1")
        if source == target:
            return None
        key = (source, target, relation_type.upper(), provider, source_url)
        existing = self._relation_index.get(key)
        if existing is not None:
            existing.evidence_ids = list(
                dict.fromkeys([*existing.evidence_ids, *(evidence_ids or [])])
            )
            for proof in evidence or []:
                if proof not in existing.evidence:
                    existing.evidence.append(proof)
            existing.confidence = max(existing.confidence, confidence)
            return existing
        relation = Relation(
            new_id(),
            source,
            target,
            relation_type.upper(),
            provider,
            created_at or utc_now(),
            source_url,
            evidence_ids or [],
            strength,
            score,
            features or {},
            contradictions or [],
            provider_run_id,
            confidence,
            evidence or [],
        )
        self.edges.append(relation)
        self._relation_index[key] = relation
        self.investigation.updated_at = relation.created_at
        return relation

    def add(self, event: Event, relation: EdgeType | None = None) -> Entity:
        kind = event.type.value
        entity = self.add_entity(kind, event.value, observed_at=event.retrieved_at)
        entity.confidence = max(entity.confidence or 0, event.confidence)
        proof = [
            self.add_evidence(
                event.source_provider,
                method=evidence_method(item.type, event.source_provider),
                source_url=item.source or event.source_url,
                collected_at=event.retrieved_at,
                excerpt=item.value,
                raw_reference=item.type,
            )
            for item in event.evidence
        ]
        if not proof:
            proof = [
                self.add_evidence(
                    event.source_provider,
                    method=evidence_method("", event.source_provider),
                    source_url=event.source_url,
                    collected_at=event.retrieved_at,
                )
            ]
        state = next(
            (tag for tag in event.tags if tag in {item.value for item in ObservationState}),
            "CONFIRMED",
        )
        if state in {"POSSIBLE", "PROBABLE"}:
            entity.state = "candidate"
        self.add_observation(
            entity.id,
            "value",
            event.value,
            provider=event.source_provider,
            state=state,
            observed_at=event.retrieved_at,
            evidence_ids=[item.id for item in proof],
        )
        parent_id = self._event_nodes.get(event.parent_id or "")
        if parent_id and relation:
            self.add_relation(
                parent_id,
                entity.id,
                relation.value,
                provider=event.source_provider,
                source_url=event.source_url,
                evidence_ids=[item.id for item in proof],
                evidence=[asdict(item) for item in event.evidence],
                confidence=event.confidence,
                created_at=event.retrieved_at,
            )
            self._recommend_pivot(entity, parent_id)
        self._event_nodes[event.id] = entity.id
        if event.parent_id is None and entity.id not in self.investigation.seed_entities:
            self.investigation.seed_entities.append(entity.id)
        return entity

    def event_entity(self, event_id: str) -> Entity | None:
        entity_id = self._event_nodes.get(event_id)
        return self.nodes.get(entity_id) if entity_id else None

    def _recommend_pivot(self, entity: Entity, parent_id: str) -> None:
        gain = PIVOT_GAIN.get(entity.type, 0.1)
        cost = 1.0 if entity.type in {"DOMAIN", "EMAIL", "USERNAME", "PHONE"} else 2.0
        priority = round(gain / cost, 3)
        candidate = self.pivot_candidates.get(entity.id)
        if candidate is None or priority > candidate.priority:
            self.pivot_candidates[entity.id] = PivotCandidate(
                entity.id,
                parent_id,
                gain,
                cost,
                priority,
                f"{entity.type.lower().replace('_', ' ')} discovered from another entity",
            )

    def add_provider_run(self, run: ProviderRun) -> None:
        self.provider_runs.append(run)

    def correlate(self, correlations: list[Correlation]) -> None:
        for item in correlations:
            left = self._canonical.get(("PROFILE", canonicalize("PROFILE", item.left_url), None))
            right = self._canonical.get(("PROFILE", canonicalize("PROFILE", item.right_url), None))
            if not left or not right or item.score < 30:
                continue
            positive = [
                {"type": proof.type, "value": proof.value, "strength": proof.weight}
                for proof in item.evidence
                if proof.weight > 0
            ]
            negative = [
                {"type": proof.type, "value": proof.value, "strength": proof.weight}
                for proof in item.evidence
                if proof.weight < 0
            ]
            source_proof_ids = list(
                dict.fromkeys(
                    proof_id
                    for observation in self.observations
                    if observation.entity_id in {left, right}
                    for proof_id in observation.evidence_ids
                )
            )
            self.add_relation(
                left,
                right,
                "POSSIBLY_SAME_AS",
                provider="correlation",
                strength="hypothesis",
                score=item.score,
                evidence_ids=source_proof_ids,
                features={"supporting": positive},
                contradictions=negative,
                evidence=[asdict(proof) for proof in item.evidence],
                confidence=item.score / 100,
            )

    def neighbors(self, entity_id: str) -> list[Entity]:
        if entity_id not in self.nodes:
            raise KeyError(entity_id)
        ids = {
            edge.target if edge.source == entity_id else edge.source
            for edge in self.edges
            if entity_id in {edge.source, edge.target}
        }
        return [self.nodes[item] for item in ids]

    def path(self, source: str, target: str) -> list[str]:
        if source not in self.nodes or target not in self.nodes:
            raise KeyError("Path endpoint is missing")
        queue = deque([(source, [source])])
        visited = {source}
        while queue:
            current, route = queue.popleft()
            if current == target:
                return route
            for edge in self.edges:
                if edge.source == current and edge.target not in visited:
                    visited.add(edge.target)
                    queue.append((edge.target, [*route, edge.target]))
        return []

    def provenance(self, entity_id: str) -> list[dict[str, Any]]:
        if entity_id not in self.nodes:
            raise KeyError(entity_id)
        result: list[dict[str, Any]] = []
        visited: set[str] = set()
        queue = deque([entity_id])
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            for edge in self.edges:
                if edge.target == current and edge.strength != "hypothesis":
                    result.append(
                        {
                            **edge.to_dict(),
                            "source_entity": self.nodes[edge.source].to_dict(),
                            "evidence_records": [
                                item.to_dict()
                                for item in self.evidence
                                if item.id in edge.evidence_ids
                            ],
                        }
                    )
                    queue.append(edge.source)
        return result

    def merge(self, left_id: str, right_id: str) -> Entity:
        if left_id not in self.nodes or right_id not in self.nodes:
            raise KeyError("Entity to merge is missing")
        left, right = self.nodes[left_id], self.nodes[right_id]
        if left.type != right.type:
            raise ValueError("Only entities of the same type can be merged")
        if left_id == right_id:
            raise ValueError("An entity cannot be merged with itself")
        merged = self.add_entity(
            left.type, left.value, attributes={"merged_from": [left_id, right_id]}
        )
        if merged.id in {left_id, right_id}:
            merged = Entity(
                new_id(),
                left.type,
                left.value,
                left.canonical_value,
                utc_now(),
                utc_now(),
                {"merged_from": [left_id, right_id]},
            )
            self.nodes[merged.id] = merged
        proof = self.add_evidence(
            "investigator", method="USER_INPUT", excerpt="Manual merge of two entity records"
        )
        self.add_relation(
            left_id, merged.id, "MERGED_INTO", provider="investigator", evidence_ids=[proof.id]
        )
        self.add_relation(
            right_id, merged.id, "MERGED_INTO", provider="investigator", evidence_ids=[proof.id]
        )
        left.state = right.state = "merged"
        return merged

    def diff(self, other: InvestigationGraph) -> dict[str, Any]:
        """Compare recorded claims; missing claims are never treated as disproved."""
        import json

        def entity_keys(graph: InvestigationGraph) -> set[tuple[str, str]]:
            return {(item.type, item.canonical_value) for item in graph.nodes.values()}

        def observation_keys(graph: InvestigationGraph) -> set[tuple[str, str, str, str, str]]:
            return {
                (
                    graph.nodes[item.entity_id].type,
                    graph.nodes[item.entity_id].canonical_value,
                    item.property,
                    json.dumps(item.value, sort_keys=True, ensure_ascii=False),
                    item.state,
                )
                for item in graph.observations
            }

        before_entities, after_entities = entity_keys(self), entity_keys(other)
        before_observations, after_observations = observation_keys(self), observation_keys(other)
        return {
            "added_entities": sorted(after_entities - before_entities),
            "not_observed_entities": sorted(before_entities - after_entities),
            "added_observations": sorted(after_observations - before_observations),
            "not_observed_observations": sorted(before_observations - after_observations),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation": self.investigation.to_dict(),
            "nodes": [item.to_dict() for item in self.nodes.values()],
            "edges": [item.to_dict() for item in self.edges],
            "observations": [item.to_dict() for item in self.observations],
            "evidence": [item.to_dict() for item in self.evidence],
            "provider_runs": [item.to_dict() for item in self.provider_runs],
            "pivot_candidates": [
                item.to_dict()
                for item in sorted(
                    self.pivot_candidates.values(), key=lambda item: item.priority, reverse=True
                )
            ],
        }
