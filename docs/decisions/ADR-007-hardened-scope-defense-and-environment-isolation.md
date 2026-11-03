# ADR-007: Hardened Scope Defense, Subprocess Isolation, and Local OAST Callback Sink

## Status
Accepted

## Context
During the critical architecture review of Pentesa v1.0, an independent review identified four critical security and scope vulnerabilities in the preliminary specification:
1. **Subprocess Secret Leakage:** Child processes spawned by the worker could inherit platform master secrets (`PENTESA_MASTER_KEY`, `POSTGRES_PASSWORD`, `JWT_SECRET_KEY`) if the system environment was copied wholesale.
2. **Wildcard Scope Boundary Bypass:** Incomplete dot-boundary checking in wildcard domain matching could allow `attacker-example.com` when `*.example.com` was configured.
3. **Multi-Record DNS Inconsistency:** When a target domain resolved to multiple `A` records (round-robin), validating one record while the socket connected to another could lead to an internal probe leakage.
4. **Out-of-Band (OAST) Blind Vulnerability Testing:** Passing `-no-interactsh` to Nuclei disabled blind SSRF and blind injection detection; using public cloud interaction servers breached the local-first sovereign principle.

## Decision
We enforce three architectural additions:
1. **Explicit Minimal Subprocess Environment:** Subprocess runners must never inherit `os.environ`. A new dictionary is constructed containing solely `PATH`, `HOME`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, and `TMPDIR`. Platform master secrets are completely inaccessible to child processes.
2. **Strict Regex Dot-Boundary Scope Matching & Unanimous Multi-Record DNS Pinning:**
   - Hostname wildcards require dot-boundary regex: `^(?:[a-zA-Z0-9-]+\.)*example\.com$`.
   - All resolved `A`/`AAAA` records must be validated as in-scope and non-private; the socket is explicitly bound to a single pre-verified IP.
3. **Local Containerized OAST Callback Sink (`pentesa-callback-sink`):**
   - A dedicated internal listener container captures out-of-band HTTP and DNS interaction callbacks.
   - Correlates blind callbacks using unique random tokens without transmitting data to third-party public cloud servers.

## Consequences & Trade-offs
### Positive:
- Complete protection against subprocess credential harvesting even if an integrated binary has an unpatched CVE.
- Bulletproof scope enforcement eliminating DNS round-robin and suffix matching bypasses.
- Sovereign detection of blind SSRF, blind XSS, and out-of-band command injection.

### Negative:
- Adds one lightweight container (`pentesa-callback-sink`) to the Docker Compose topology.

