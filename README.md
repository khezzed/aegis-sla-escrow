# AEGIS — Autonomous Cloud SLA & API Uptime Performance Escrow on GenLayer

**AEGIS** (`contracts/aegis_sla_escrow.py`) is a GenLayer Intelligent Contract that replaces manual, provider-controlled SLA billing credit disputes with decentralized AI-validator adjudication over live HTTPS incident telemetry and post-mortems.

---

## Architectural Overview

1. **Pinned GenVM Runner (`v0.2.16`)**:
   - Uses `# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }`.
2. **Immutable Incident-Scoped SLO Charter**:
   - Validated and canonicalized at deployment (`__init__`) along with its SHA-256 digest (`charter_hash`).
   - Enforces two objective incident-scoped SLOs over `[incident_start_ts, incident_end_ts]`:
     - `SLO_RECOVERY_TIME` (`observed_ttr_minutes`, cross-checked within $\pm 1\text{ min}$ of $\lceil(\texttt{incident\_end\_ts} - \texttt{incident\_start\_ts}) / 60\rceil$).
     - `SLO_LATENCY_P99` (`observed_p99_ms`).
3. **Deterministic Scheduled Maintenance Carve-Out Verification**:
   - Supports `CARVEOUT_SCHEDULED_MAINTENANCE` only when the telemetry provides valid timestamps (`maintenance_announced_ts`, `maintenance_window_start_ts`, `maintenance_window_end_ts`) that deterministically satisfy:
     - Advance notice: `maintenance_window_start_ts - maintenance_announced_ts >= min_advance_notice_seconds`
     - Window duration: `maintenance_window_end_ts - maintenance_window_start_ts <= max_maintenance_window_minutes * 60`
     - Interval containment: `incident_start_ts >= maintenance_window_start_ts` and `incident_end_ts <= maintenance_window_end_ts`
   - Excuses only the SLO IDs listed in `excused_slo_ids`. Unverified maintenance claims (missing timestamps) resolve to `INCONCLUSIVE` (`EXPECTED:UNVERIFIED_CARVEOUT_EVIDENCE`), never `NO_BREACH`.
   - Failed maintenance carve-out checks leave the measured SLO violations active and compute final severity (`CRITICAL_BREACH` or `DEGRADED_BREACH`) from those remaining violations.
4. **Five-Bucket Financial Accounting & Terminal-Only Stake Settlement**:
   - Maintains five disjoint `u256` buckets (`free_collateral`, `locked_collateral`, `provider_fee_revenue`, `outstanding_stakes`, `total_claimable_balances`) and cumulative flow counters (`total_inbound_wei`, `total_outbound_wei`) satisfying:
     $$\texttt{total\_inbound\_wei} - \texttt{total\_outbound\_wei} = \texttt{free\_collateral} + \texttt{locked\_collateral} + \texttt{provider\_fee\_revenue} + \texttt{outstanding\_stakes} + \texttt{total\_claimable\_balances}$$
   - Dispute stakes remain in `STAKE_HELD` across `INCONCLUSIVE` retries and transition to `STAKE_REFUNDED` or `STAKE_FORFEITED` exclusively when a report reaches a terminal state (`REPORT_RESOLVED` or `REPORT_EXPIRED_INCONCLUSIVE`).
5. **15-Field Consensus Envelope & Payload-Grounded Citations**:
   - Both `leader_fn` and `validator_fn` independently fetch the canonicalized HTTPS URL, verify bounded verbatim citations (`ttr_citation`, `p99_citation`) against the fetched payload text, and compare all 15 envelope fields (`outcome`, `violated_slo_ids`, `carveout_ids`, `telemetry_complete`, `status_code`, `incident_start_ts`, `incident_end_ts`, `observed_ttr_minutes`, `observed_p99_ms`, `maintenance_claimed`, `maintenance_announced_ts`, `maintenance_window_start_ts`, `maintenance_window_end_ts`, `ttr_citation`, `p99_citation`).

---

## Repository Structure

```text
aegis-sla-escrow/
├── contracts/
│   └── aegis_sla_escrow.py                      # AEGIS Intelligent Contract
├── tests/
│   ├── direct/
│   │   ├── conftest.py                          # In-memory GenVM harness for fast deterministic unit testing
│   │   ├── test_charter_and_accounting.py       # Charter validation, payable guards, 5-bucket conservation, expiry bounds
│   │   ├── test_url_and_carveout_verification.py# URL canonicalization, HTTP bounds, deterministic maintenance verification
│   │   └── test_consensus_and_adversarial.py    # Prompt injection, retry stake retention, citation checks, 4-outcome deltas
│   └── integration/
│       └── test_aegis_integration.py            # Live GenLayer Studio / GLSim integration suite
├── gltest.config.yaml                           # GenLayer test runner configuration
├── pyproject.toml                               # Project metadata & pytest configuration
├── requirements.txt                             # Pinned tool dependencies
└── README.md
```

---

## Clean Environment Setup

Create an isolated virtual environment and install dependencies exclusively from `requirements.txt`:

**Linux / macOS (`bash`)**:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (`powershell`)**:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

---

## Verification & Quality Gates

Run all commands from the repository root with `.venv` activated (on Windows PowerShell, set `$env:PYTHONUTF8 = "1"` so `genvm-lint typecheck` can print Unicode status symbols cleanly):

### 1. Official Contract Linter & AST Validator
```bash
genvm-lint check contracts/aegis_sla_escrow.py --json
```

### 2. GenVM SDK Type Checker (Pyright)
```bash
genvm-lint typecheck contracts/aegis_sla_escrow.py
```

### 3. Direct-Mode Unit & Adversarial Tests (`pytest`)
```bash
pytest tests/direct/ -v
```

### 4. Integration Suite (`gltest`)
```bash
gltest tests/integration/ -v -s
```

---

## Testing Scope: Direct-Mode vs. Live Consensus & Settlement

- **Direct-Mode Suite (`tests/direct/` — 18 passed)**:
  Runs entirely in-process against a deterministic GenVM mock harness (`tests/direct/conftest.py`) without requiring a live localnet node. It directly verifies all contract state transitions, `@gl.public.write.payable` payment checks, the 5-bucket conservation invariant (`total_inbound_wei - total_outbound_wei == sum(buckets)`), URL canonicalization and SSRF/redirect defenses, deterministic maintenance carve-out math, bounded verbatim citation checks, `leader_fn` / `validator_fn` equivalence rejection of Byzantine proposals, and `EthSend` transfer emission across all four outcomes (`CRITICAL_BREACH`, `DEGRADED_BREACH`, `NO_BREACH`, `INCONCLUSIVE`).
- **Live Integration Suite (`tests/integration/` — 4 tests; skipped when local GenLayer RPC is unavailable)**:
  Targets a live GenLayer Studio or `glsim` RPC endpoint (`http://127.0.0.1:4000/api`) to execute multi-validator Optimistic Democracy consensus and L2 EVM value settlement on GenLayer Chain. When the local GenLayer RPC (`http://127.0.0.1:4000/api`) is not running in the test environment, `gltest` skips these 4 tests cleanly with an explicit diagnostic reason rather than reporting false passes.

---

## Live Deployment (GenLayer Studio / `studionet`)

- **Contract Address**: `0x9094C38E7aa90d7eFCc6D1A67D47100e1163C793`
- **GenLayer Studio Explorer**: [https://explorer-studio.genlayer.com/address/0x9094C38E7aa90d7eFCc6D1A67D47100e1163C793](https://explorer-studio.genlayer.com/address/0x9094C38E7aa90d7eFCc6D1A67D47100e1163C793)
- **Deployment Transaction Hash**: `0x030ba80f3b91f416606e9b59179800f0790ef90acc32e1f235245d4cef0e3eb6` (`status: ACCEPTED`)
- **Charter SHA-256 Digest (`charter_hash`)**: `18adb130c378c3ad7376c7329c0de962381623406579b90fdf231cd37e813674`


