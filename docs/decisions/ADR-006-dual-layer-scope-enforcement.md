# ADR-006: Dual-Layer Scope Enforcement (Application URL Router + Network Egress Proxy with DNS Pinning)

## Status
Accepted

## Context
Exceeding authorized target scope during a penetration test is a critical legal and ethical violation. In complex web applications, modern targets use single-page applications, dynamic redirects, third-party CDNs, and multiple DNS records.

Standard application-level URL checks (`if url.startswith(allowed_domain)`) are vulnerable to multiple bypasses:
1. **DNS Rebinding:** An attacker-controlled hostname resolves to an authorized IP during the application check, but resolves to an unauthorized private internal IP (`127.0.0.1` or `169.254.169.254`) when the HTTP client establishes the TCP connection.
2. **Dynamic Redirect Traversal:** An in-scope URL redirects (`302`) to an external third-party payment or analytics domain, and the HTTP client follows the redirect automatically.
3. **Subprocess Tool Leakage:** A tool binary might have an internal crawling routine that traverses external links if not restricted at the network socket layer.

## Decision
We mandate a **Dual-Layer Scope Enforcement Architecture**:

1. **Layer 1 (Application-Level Guard):** All URLs queued by agents or worker tasks are pre-validated against approved domains, wildcard rules, and regex exclusions.
2. **Layer 2 (Network Socket Egress Proxy with DNS Pinning):** All outbound traffic from all tools and HTTP clients is routed through an internal forward proxy (`pentesa-egress-proxy`). The proxy:
   - Performs DNS resolution in an isolated resolver.
   - Asserts the destination IP address against authorized CIDR ranges.
   - Opens the TCP socket directly to that specific validated IP (DNS Pinning), passing the original hostname only in the HTTP `Host` header and TLS SNI.
   - Disables automatic redirect following and inspects `Location` headers before traversal.

## Consequences & Trade-offs
### Positive:
- Mathematical guarantee: Zero TCP connections can be established to out-of-scope IP addresses or hostnames.
- Complete neutralization of DNS rebinding attacks and inadvertent redirect leakage.
- Uniform scope enforcement across all third-party CLI tools (Nuclei, Katana, Ffuf) via standard `HTTP_PROXY` environment variables.

### Negative:
- Minor latency overhead (~2–5ms) added to outbound requests for proxy socket inspection and local DNS caching.
- Requires maintaining the lightweight Python asyncio forward proxy container.
