"""Unit tests for attack surface topology graph generator."""

import uuid
from packages.schemas.discovery import NodeType
from services.discovery_engine.graph import build_attack_surface_graph


def test_build_attack_surface_graph_hierarchy():
    """Verify nodes and edges construction connecting domain, subdomain, endpoint, parameter, and tech."""
    domains = [
        {"fqdn": "target.com", "is_active": True, "resolved_ips": ["93.184.216.34"]},
        {"fqdn": "api.target.com", "is_active": True, "resolved_ips": ["93.184.216.35"]}
    ]
    endpoints = [
        {
            "id": uuid.uuid4(),
            "fqdn": "api.target.com",
            "url_path": "/api/v1/users",
            "http_method": "GET",
            "parameter_schema": {
                "query": [{"name": "page", "type": "integer"}],
                "path": []
            },
            "auth_required": True
        }
    ]
    technologies = [
        {"name": "Nginx", "version": "1.24", "category": "WEB_SERVER"}
    ]

    graph = build_attack_surface_graph(domains, endpoints, technologies)

    # Verify node types
    node_types = {n.node_type for n in graph.nodes}
    assert NodeType.ROOT_DOMAIN in node_types
    assert NodeType.SUBDOMAIN in node_types
    assert NodeType.ENDPOINT in node_types
    assert NodeType.PARAMETER in node_types
    assert NodeType.TECHNOLOGY in node_types

    # Verify edges
    edge_relations = {e.relationship for e in graph.edges}
    assert "SUBDOMAIN_OF" in edge_relations
    assert "EXPOSES" in edge_relations
    assert "ACCEPTS" in edge_relations
    assert "POWERED_BY" in edge_relations

    # Verify stats
    assert graph.stats["domains"] >= 2
    assert graph.stats["endpoints"] == 1
    assert graph.stats["parameters"] == 1
    assert graph.stats["technologies"] == 1

