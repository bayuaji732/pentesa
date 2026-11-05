"""Pydantic schemas for Attack Surface Discovery: domains, endpoints, technologies, and topology graph."""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class HttpMethod(str, Enum):
    """Standard HTTP methods."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ParameterLocation(str, Enum):
    """Location of an extracted parameter."""
    QUERY = "query"
    BODY = "body"
    PATH = "path"
    HEADER = "header"
    COOKIE = "cookie"


class ParameterItem(BaseModel):
    """Single extracted parameter schema."""
    name: str
    location: ParameterLocation = ParameterLocation.QUERY
    type: str = "string"  # string, integer, boolean, object, array
    required: bool = False
    example: Optional[Any] = None
    description: Optional[str] = None


class ParameterSchema(BaseModel):
    """Structured grouping of parameters extracted for an endpoint."""
    query: List[ParameterItem] = Field(default_factory=list)
    body: List[ParameterItem] = Field(default_factory=list)
    path: List[ParameterItem] = Field(default_factory=list)
    headers: List[ParameterItem] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Domain Schemas
# ---------------------------------------------------------------------------

class DiscoveredDomainBase(BaseModel):
    """Base fields for discovered domain."""
    fqdn: str = Field(min_length=1, max_length=255)
    resolved_ips: List[str] = Field(default_factory=list)
    discovery_source: str = "crawler"
    is_active: bool = True


class DiscoveredDomainCreate(DiscoveredDomainBase):
    """Payload to register a discovered domain."""
    pass


class DiscoveredDomainResponse(DiscoveredDomainBase):
    """Discovered domain representation."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    created_at: datetime


# ---------------------------------------------------------------------------
# Endpoint Schemas
# ---------------------------------------------------------------------------

class EndpointBase(BaseModel):
    """Base fields for an endpoint."""
    fqdn: str = Field(min_length=1, max_length=255)
    url_path: str = Field(min_length=1)
    http_method: str = "GET"
    parameter_schema: Dict[str, Any] = Field(default_factory=dict)
    content_type: Optional[str] = None
    auth_required: bool = False
    discovery_source: str = "CRAWLER"
    testing_status: str = "Discovered"


class EndpointCreate(EndpointBase):
    """Payload to add an endpoint manually or programmatically."""
    domain_id: Optional[uuid.UUID] = None


class EndpointUpdate(BaseModel):
    """Payload to update endpoint metadata or testing status."""
    testing_status: Optional[str] = None
    auth_required: Optional[bool] = None
    parameter_schema: Optional[Dict[str, Any]] = None
    content_type: Optional[str] = None


class EndpointResponse(EndpointBase):
    """Detailed endpoint response representation."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    domain_id: Optional[uuid.UUID] = None
    created_at: datetime
    updated_at: datetime


class EndpointListResponse(BaseModel):
    """Paginated endpoint list response."""
    total: int
    items: List[EndpointResponse]


# ---------------------------------------------------------------------------
# Technology Schemas
# ---------------------------------------------------------------------------

class TechnologyBase(BaseModel):
    """Base fields for detected technology fingerprint."""
    name: str = Field(min_length=1, max_length=100)
    version: Optional[str] = None
    category: str = "UNKNOWN"
    confidence: int = Field(default=100, ge=1, le=100)
    detected_on_url: Optional[str] = None


class TechnologyCreate(TechnologyBase):
    """Payload to record a detected technology."""
    pass


class TechnologyResponse(TechnologyBase):
    """Technology fingerprint representation."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    created_at: datetime


# ---------------------------------------------------------------------------
# Cookie & Security Header Schemas
# ---------------------------------------------------------------------------

class CookieResponse(BaseModel):
    """Discovered cookie representation."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    name: str
    domain: str
    path: str
    is_secure: bool
    is_httponly: bool
    samesite: Optional[str] = None
    created_at: datetime


class SecurityHeaderResponse(BaseModel):
    """Observed security header representation."""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    endpoint_id: Optional[uuid.UUID] = None
    header_name: str
    header_value: str
    is_secure_standard: Optional[bool] = None
    created_at: datetime


# ---------------------------------------------------------------------------
# Topology Graph Schemas
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    """Attack surface graph node classification."""
    ROOT_DOMAIN = "ROOT_DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    ENDPOINT = "ENDPOINT"
    PARAMETER = "PARAMETER"
    TECHNOLOGY = "TECHNOLOGY"


class GraphNode(BaseModel):
    """Single node in the attack surface topology graph."""
    id: str
    label: str
    node_type: NodeType
    data: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    """Directed relationship edge between attack surface nodes."""
    id: str
    source: str
    target: str
    relationship: str  # HOSTS, EXPOSES, ACCEPTS, POWERED_BY


class AttackSurfaceGraphResponse(BaseModel):
    """Full graph structure for frontend force-directed visualization."""
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    stats: Dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Crawl Request & Response Schemas
# ---------------------------------------------------------------------------

class CrawlRequest(BaseModel):
    """Parameters for launching an automated attack surface discovery crawl."""
    seed_urls: Optional[List[str]] = Field(default=None, description="Initial URLs to seed the crawl; defaults to project target domains")
    max_depth: int = Field(default=3, ge=1, le=10, description="Maximum link crawl recursion depth")
    max_pages: int = Field(default=50, ge=1, le=500, description="Maximum distinct pages to crawl")
    respect_robots_txt: bool = Field(default=True, description="Fetch and parse /robots.txt for endpoints")
    parse_sitemap: bool = Field(default=True, description="Fetch and parse /sitemap.xml for endpoints")
    extract_js_routes: bool = Field(default=True, description="Analyze referenced JS bundles for API endpoints")
    detect_technologies: bool = Field(default=True, description="Run technology fingerprinting on crawled responses")


class CrawlSummaryResponse(BaseModel):
    """Summary result returned upon completing or starting a crawl."""
    status: str  # COMPLETED, FAILED, PARTIAL
    total_urls_visited: int
    endpoints_discovered: int
    technologies_detected: int
    domains_discovered: int
    errors: List[str] = Field(default_factory=list)

