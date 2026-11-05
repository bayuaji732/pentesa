"""Attack surface topology graph generator."""

from typing import Any, Dict, List, Set
from packages.schemas.discovery import (
    AttackSurfaceGraphResponse,
    GraphEdge,
    GraphNode,
    NodeType
)


def build_attack_surface_graph(
    domains: List[Any],
    endpoints: List[Any],
    technologies: List[Any]
) -> AttackSurfaceGraphResponse:
    """
    Construct a directed graph connecting domains, subdomains, endpoints, parameters, and technologies.
    """
    nodes: Dict[str, GraphNode] = {}
    edges: List[GraphEdge] = []
    seen_edge_ids: Set[str] = set()

    def add_edge(source_id: str, target_id: str, relationship: str):
        edge_id = f"e:{source_id}->{target_id}:{relationship}"
        if edge_id not in seen_edge_ids:
            seen_edge_ids.add(edge_id)
            edges.append(GraphEdge(
                id=edge_id,
                source=source_id,
                target=target_id,
                relationship=relationship
            ))

    # 1. Process Domains
    for d in domains:
        fqdn = getattr(d, "fqdn", None) or (d.get("fqdn") if isinstance(d, dict) else "")
        if not fqdn:
            continue

        parts = fqdn.split(".")
        is_subdomain = len(parts) > 2

        node_id = f"domain:{fqdn}"
        node_type = NodeType.SUBDOMAIN if is_subdomain else NodeType.ROOT_DOMAIN
        nodes[node_id] = GraphNode(
            id=node_id,
            label=fqdn,
            node_type=node_type,
            data={
                "fqdn": fqdn,
                "is_active": getattr(d, "is_active", True) or (d.get("is_active", True) if isinstance(d, dict) else True),
                "resolved_ips": getattr(d, "resolved_ips", []) or (d.get("resolved_ips", []) if isinstance(d, dict) else [])
            }
        )

        # Connect subdomain to root domain if present
        if is_subdomain:
            root_fqdn = ".".join(parts[-2:])
            root_node_id = f"domain:{root_fqdn}"
            if root_node_id not in nodes:
                nodes[root_node_id] = GraphNode(
                    id=root_node_id,
                    label=root_fqdn,
                    node_type=NodeType.ROOT_DOMAIN,
                    data={"fqdn": root_fqdn}
                )
            add_edge(root_node_id, node_id, "SUBDOMAIN_OF")

    # 2. Process Endpoints
    for ep in endpoints:
        ep_id = str(getattr(ep, "id", None) or (ep.get("id") if isinstance(ep, dict) else ""))
        fqdn = getattr(ep, "fqdn", "") or (ep.get("fqdn", "") if isinstance(ep, dict) else "")
        path = getattr(ep, "url_path", "/") or (ep.get("url_path", "/") if isinstance(ep, dict) else "/")
        method = getattr(ep, "http_method", "GET") or (ep.get("http_method", "GET") if isinstance(ep, dict) else "GET")
        params = getattr(ep, "parameter_schema", {}) or (ep.get("parameter_schema", {}) if isinstance(ep, dict) else {})
        auth_req = getattr(ep, "auth_required", False) or (ep.get("auth_required", False) if isinstance(ep, dict) else False)

        ep_node_id = f"endpoint:{ep_id}"
        nodes[ep_node_id] = GraphNode(
            id=ep_node_id,
            label=f"{method} {path}",
            node_type=NodeType.ENDPOINT,
            data={
                "id": ep_id,
                "fqdn": fqdn,
                "url_path": path,
                "http_method": method,
                "auth_required": auth_req
            }
        )

        # Link from domain to endpoint
        domain_node_id = f"domain:{fqdn}"
        if domain_node_id not in nodes:
            nodes[domain_node_id] = GraphNode(
                id=domain_node_id,
                label=fqdn,
                node_type=NodeType.SUBDOMAIN if len(fqdn.split(".")) > 2 else NodeType.ROOT_DOMAIN,
                data={"fqdn": fqdn}
            )
        add_edge(domain_node_id, ep_node_id, "EXPOSES")

        # 3. Process Parameters for Endpoint
        if isinstance(params, dict):
            for loc, param_list in params.items():
                if isinstance(param_list, list):
                    for p in param_list:
                        p_name = p.get("name") if isinstance(p, dict) else getattr(p, "name", None)
                        p_type = p.get("type", "string") if isinstance(p, dict) else getattr(p, "type", "string")
                        if p_name:
                            p_node_id = f"param:{ep_id}:{p_name}"
                            nodes[p_node_id] = GraphNode(
                                id=p_node_id,
                                label=f"{p_name} ({loc})",
                                node_type=NodeType.PARAMETER,
                                data={
                                    "name": p_name,
                                    "location": loc,
                                    "type": p_type
                                }
                            )
                            add_edge(ep_node_id, p_node_id, "ACCEPTS")

    # 4. Process Technologies
    for tech in technologies:
        t_name = getattr(tech, "name", "") or (tech.get("name", "") if isinstance(tech, dict) else "")
        t_ver = getattr(tech, "version", None) or (tech.get("version") if isinstance(tech, dict) else None)
        t_cat = getattr(tech, "category", "UNKNOWN") or (tech.get("category", "UNKNOWN") if isinstance(tech, dict) else "UNKNOWN")

        if not t_name:
            continue

        tech_node_id = f"tech:{t_name}"
        if tech_node_id not in nodes:
            nodes[tech_node_id] = GraphNode(
                id=tech_node_id,
                label=f"{t_name} {t_ver or ''}".strip(),
                node_type=NodeType.TECHNOLOGY,
                data={
                    "name": t_name,
                    "version": t_ver,
                    "category": t_cat
                }
            )

        # Connect to root domains as overall technology stack
        for d_id, d_node in list(nodes.items()):
            if d_node.node_type in (NodeType.ROOT_DOMAIN, NodeType.SUBDOMAIN):
                add_edge(d_id, tech_node_id, "POWERED_BY")

    stats = {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "domains": sum(1 for n in nodes.values() if n.node_type in (NodeType.ROOT_DOMAIN, NodeType.SUBDOMAIN)),
        "endpoints": sum(1 for n in nodes.values() if n.node_type == NodeType.ENDPOINT),
        "parameters": sum(1 for n in nodes.values() if n.node_type == NodeType.PARAMETER),
        "technologies": sum(1 for n in nodes.values() if n.node_type == NodeType.TECHNOLOGY)
    }

    return AttackSurfaceGraphResponse(
        nodes=list(nodes.values()),
        edges=edges,
        stats=stats
    )
