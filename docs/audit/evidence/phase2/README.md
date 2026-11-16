# Phase 2 Machine-Captured Evidence Directory

## Evidence Policy & Integrity Rule

In accordance with the Master Audit Prompt Execution Rules and Amendments:
1. **Machine-Captured Invariant:** Every raw evidence file (`.txt`) in this directory is generated directly via automated test harnesses and captured via script/tee. Files are **NEVER** manually hand-edited.
2. **Forensic Header Requirement:** Every machine-captured evidence artifact begins with an automated header capturing:
   - UTC timestamp (`Timestamp (UTC)`)
   - Git commit SHA and dirty flag (`Git SHA`)
   - Exact execution command line (`Command`)
   - Database engine version (`Database`, e.g. `SELECT version()`)
   - Execution mode (`Execution Mode: running stack (HTTP + PostgreSQL 16)`)
3. **Cryptographic Integrity Ledger:** All active artifacts, historical superseded records, and screenshots are hashed and recorded in `MANIFEST.sha256`. Any modification to an evidence file invalidates the checksum ledger.
4. **Correction Process:** If an evidence file contains an error or needs clarification, the raw file is not edited; corrections and reconciliations must be recorded in formal addenda (e.g., `2A-addendum.md`) or defect logs.
5. **Verification:** Integrity is provable at any time via:
   ```bash
   sha256sum -c MANIFEST.sha256
   ```
