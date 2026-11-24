# ADR-004: API Schema Completeness & Keyset Cursor Pagination

> **Document Identifier:** `ADR-004-API-CONTRACT-PAGINATION`  
> **Status:** ACCEPTED  
> **Date:** 2026-11-24  
> **Auditors / Authors:** API & Data Architecture Evaluation Team  
> **Reference Baseline:** `P1-FIND-02`, `DEFECT-SCAL-01`, `P8-TC-SCAL-01`

---

## 1. Context & Problem Statement

Phase 1/7/8 evaluations identified two critical data contract defects in the REST API:
1. **Incomplete `FindingResponse` Schema (`P1-FIND-02`):**
   - `packages/schemas/finding.py:FindingResponse` serializes `endpoint_id: Optional[uuid.UUID]`, but omits root `endpoint`, `method`, `target`, and `parameter` string fields.
   - Result: Frontend dashboard, PDF reporter, and automated benchmark scorers must perform $N+1$ secondary network joins or receive empty target strings (strict completeness: 46.7%).
2. **Missing Keyset Cursor Pagination (`DEFECT-SCAL-01` / `P8-TC-SCAL-01`):**
   - `GET /api/v1/projects/{id}/endpoints` relies on SQL `OFFSET / LIMIT` pagination. At 10,000+ items, database query cost scales linearly $O(N)$.
   - `GET /api/v1/projects/{id}/findings` has **zero** pagination parameters (`limit` / `offset` absent).

---

## 2. Decision

1. **Normalize `FindingResponse`:** Enrich `FindingResponse` with first-class fields: `endpoint: str`, `method: str`, `target: str`, `parameter: str`, and `reproduction_curl: Optional[str]`. Eagerly load `endpoint_rel` via SQLAlchemy `.selectinload(Finding.endpoint_rel)`.
2. **Implement Keyset Cursor Pagination:**
   - Add cursor pagination to both `GET /api/v1/projects/{id}/endpoints` and `GET /api/v1/projects/{id}/findings`.
   - Cursor Token Format: URL-safe Base64-encoded tuple `timestamp_epoch_ms:record_uuid`.
   - SQL Query Pattern: `WHERE (created_at, id) < (:cursor_ts, :cursor_id) ORDER BY created_at DESC, id DESC LIMIT :limit`.
   - Response Envelope: Include `next_cursor: Optional[str]` and `has_more: bool`.
   - Backward Compatibility: Retain `offset` / `limit` parameters for existing UI consumers.

---

## 3. Benefits & Performance

- Eliminates $N+1$ endpoint lookups across frontend and report generation.
- Guarantees $O(1)$ database execution time regardless of scale (10,000 to 1,000,000 records).
- Resolves `P1-FIND-02` and `DEFECT-SCAL-01`.
