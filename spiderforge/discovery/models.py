from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    path_template: str = ""
    host: str = ""
    content_type: str | None = None
    status_code: int | None = None
    source: str = "crawl"  # crawl | js | swagger | graphql | hidden | form
    parameters: list[str] = field(default_factory=list)


@dataclass
class ParameterProfile:
    url: str
    name: str
    source: str  # url | form | js | swagger
    method: str = "GET"
    inferred_type: str = "string"
    sample_values: list[str] = field(default_factory=list)
    confidence: float = 0.5


@dataclass
class JSFinding:
    source_url: str
    endpoints: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    websockets: list[str] = field(default_factory=list)
    source_maps: list[str] = field(default_factory=list)
    interesting_strings: list[str] = field(default_factory=list)
    fetch_calls: list[str] = field(default_factory=list)
    confidence: float = 0.5
    size_bytes: int = 0
    error: str | None = None


@dataclass
class APICluster:
    base_path: str
    endpoints: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    auth_hint: str | None = None
    api_kind: str = "rest"  # rest | graphql | swagger | json


@dataclass
class SwaggerSpec:
    url: str
    version: str | None = None
    title: str | None = None
    base_path: str | None = None
    endpoints: list[Endpoint] = field(default_factory=list)
    error: str | None = None


@dataclass
class GraphQLInfo:
    url: str
    detected: bool = False
    introspection_enabled: bool = False
    schema_types: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class DiscoveryResult:
    seed: str
    endpoints: list[Endpoint] = field(default_factory=list)
    parameters: list[ParameterProfile] = field(default_factory=list)
    api_clusters: list[APICluster] = field(default_factory=list)
    js_findings: list[JSFinding] = field(default_factory=list)
    swagger_specs: list[SwaggerSpec] = field(default_factory=list)
    graphql: list[GraphQLInfo] = field(default_factory=list)
    hidden_paths: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        from dataclasses import asdict
        return {
            "seed": self.seed,
            "endpoints": [asdict(e) for e in self.endpoints],
            "parameters": [asdict(p) for p in self.parameters],
            "api_clusters": [asdict(c) for c in self.api_clusters],
            "js_findings": [asdict(j) for j in self.js_findings],
            "swagger_specs": [asdict(s) for s in self.swagger_specs],
            "graphql": [asdict(g) for g in self.graphql],
            "hidden_paths": list(self.hidden_paths),
            "out_of_scope": list(self.out_of_scope),
            "errors": list(self.errors),
            "stats": dict(self.stats),
        }
