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
   - Both `leader_fn` and `validator_fn` independently fetch the canonicalized HTTPS URL and evaluate the 8 deterministic validation gates (returning non-terminal `INCONCLUSIVE` on `EXPECTED:INCIDENT_MISMATCH` so wrong URLs or extraction errors never forfeit a legitimate claim or stake).
   - `validator_fn` enforces exact equality on the core verdict fields (`outcome`, `violated_slo_ids`, `carveout_ids`, `telemetry_complete`, `status_code`, `maintenance_claimed`), verifies that the leader's citations (`ttr_citation`, `p99_citation`) are grounded verbatim in the validator's independently fetched payload, checks tight numeric tolerances ($\pm 60\text{s}$ on timestamps, $\pm 1\text{ min}$ on TTR, $\pm 5\text{ ms}$ on p99), and re-runs the deterministic gates on the leader's extracted metrics to confirm identical verdict derivation.

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
│       └── test_aegis_integration.py            # Live GenLayer Studio (studionet) / GLSim integration suite
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

### 4. Live Consensus Integration Suite (`gltest` on `studionet`)
```bash
gltest tests/integration/ -v --network studionet
```

---

## Testing Scope: Direct-Mode vs. Live Consensus & Settlement

- **Direct-Mode Suite (`tests/direct/` — 20 passed)**:
  Runs in-process against a deterministic GenVM mock harness (`tests/direct/conftest.py`). It verifies all contract state transitions, `@gl.public.write.payable` payment checks, the 5-bucket conservation invariant (`total_inbound_wei - total_outbound_wei == sum(buckets)`), URL canonicalization and SSRF/redirect defenses, deterministic maintenance carve-out math, non-terminal `INCONCLUSIVE` handling on incident-identity mismatch (`AT-17`), `validator_fn` tolerance for harmless citation wording differences grounded in the payload (`AT-18`), Byzantine leader rejection, and `EthSend` transfer emission across all four outcomes (`CRITICAL_BREACH`, `DEGRADED_BREACH`, `NO_BREACH`, `INCONCLUSIVE`).
- **Live Integration Suite (`tests/integration/` — 4 passed on `studionet`)**:
  Executes end-to-end multi-validator Optimistic Democracy consensus and L2 EVM value settlement on GenLayer `studionet` (`https://studio.genlayer.com/api`), verifying concrete outcomes and 5-bucket accounting deltas across `CRITICAL_BREACH` (with `claim_balance()` payout), `INCONCLUSIVE` (`EXPECTED:INCIDENT_MISMATCH` stake retention), HTTP 404 recovery via `reevaluate_incident_report()` to `DEGRADED_BREACH`, and verified `CARVEOUT_SCHEDULED_MAINTENANCE` settling as `NO_BREACH`.

---

## Live Deployment (GenLayer Studio / `studionet`)

- **Contract Address**: `0x60f6b923f21D3d5df978EbeEa46F343639fAe934`
- **GenLayer Studio Explorer**: [https://explorer-studio.genlayer.com/address/0x60f6b923f21D3d5df978EbeEa46F343639fAe934](https://explorer-studio.genlayer.com/address/0x60f6b923f21D3d5df978EbeEa46F343639fAe934)
- **Charter SHA-256 Digest (`charter_hash`)**: `18adb130c378c3ad7376c7329c0de962381623406579b90fdf231cd37e813674`
