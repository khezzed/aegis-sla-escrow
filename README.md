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
   - Both `leader_fn` and `validator_fn` independently fetch the canonicalized HTTPS URL and evaluate 8 deterministic validation gates (returning non-terminal `INCONCLUSIVE` on `EXPECTED:INCIDENT_MISMATCH` so wrong URLs or extraction errors never forfeit a legitimate claim or stake).
   - Storage state is fully snapshotted into local variables before nondeterministic closures with zero `self` references.
   - Citations (`ttr_citation`, `p99_citation`) are deterministically verified as grounded in the raw payload text and canonicalized against payload clauses matching the extracted numeric metrics (`\b{metric_val}\b`), guaranteeing deterministic agreement across validators.
   - `validator_fn` enforces exact 15-field equality across every stored and state-affecting field in the consensus envelope (`leader_env[k] == val_env[k]`), rejecting any Byzantine or perturbed leader proposal.

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

## Testing Scope: Direct-Mode vs. Live Consensus & Settlement

- **Direct-Mode Suite (`tests/direct/` — 22 passed)**:
  Runs in-process against a deterministic GenVM mock harness (`tests/direct/conftest.py`). It verifies all contract state transitions, `@gl.public.write.payable` payment checks, the 5-bucket conservation invariant (`total_inbound_wei - total_outbound_wei == sum(buckets)`), URL canonicalization and SSRF/redirect defenses, deterministic maintenance carve-out math, non-terminal `INCONCLUSIVE` handling on incident-identity mismatch (`AT-17`), `validator_fn` acceptance of canonicalized grounded payload citations (`AT-18`), Byzantine adversarial leader rejection on forged fields (`AT-19`), fail-closed behavior on invalid UTF-8 bytes and empty payloads (`AT-20`), and `EthSend` transfer emission across all four outcomes (`CRITICAL_BREACH`, `DEGRADED_BREACH`, `NO_BREACH`, `INCONCLUSIVE`).
- **Live Integration Suite (`tests/integration/` — 4 passed on `studionet`)**:
  Executes end-to-end multi-validator Optimistic Democracy consensus and L2 EVM value settlement on GenLayer `studionet` (`https://studio.genlayer.com/api`), verifying concrete outcomes and 5-bucket accounting deltas across `CRITICAL_BREACH` (with `claim_balance()` payout), `INCONCLUSIVE` (`EXPECTED:INCIDENT_MISMATCH` stake retention), HTTP 404 recovery via `reevaluate_incident_report()` to `DEGRADED_BREACH`, and verified `CARVEOUT_SCHEDULED_MAINTENANCE` settling as `NO_BREACH`.

---

## Live Deployment (GenLayer Studio / `studionet`)

- **Contract Address**: [`0x72Fc1e32b4E6A3434B8712d188C6b5B0Ae1FEEE7`](https://explorer-studio.genlayer.com/address/0x72Fc1e32b4E6A3434B8712d188C6b5B0Ae1FEEE7)
- **Deployed Commit**: [`f87ce6486e0262b81821dc4a6f34a9aca784c52b`](https://github.com/khezzed/aegis-sla-escrow/commit/f87ce6486e0262b81821dc4a6f34a9aca784c52b)
- **Git Blob SHA-1 (`contracts/aegis_sla_escrow.py`)**: `530d77e45959a9d94f9bd7672eaa59b0b8b077e8`
- **Charter SHA-256 Digest (`charter_hash`)**: `14c81abdf441d57450ba042e89f3bc979db4a146ad2d58631a61eba3e57610b7`
- **Release Manifest**: [`release_manifest.json`](release_manifest.json) (complete record of toolchain, commit SHA, Git blob hash, constructor args, every live transaction, validator votes, leader execution results, and read-backs)

### Key On-Chain Demonstration Transactions (`studionet`)

| Action | Transaction Hash | Status | Leader Result | Outcome / Effect |
| :--- | :--- | :--- | :--- | :--- |
| **Deploy Contract** | [`0x7803...15ef6`](https://explorer-studio.genlayer.com/transactions/0x780350ac8e3bf30d0f8361c1e8dfcbe898e7653d2c7fc54bcdf349e493815ef6) | `FINALIZED` | `SUCCESS` | Contract deployed with immutable charter |
| **Deposit Collateral** | [`0x30ad...c5fe`](https://explorer-studio.genlayer.com/transactions/0x30adbd35b7508434f351dc8c4e18b74dbd93c8a6b2c1f53f823edce3b4e4c5fe) | `FINALIZED` | `SUCCESS` | Provider deposits 500 wei into `free_collateral` |
| **Register Subscription #1** | [`0x5dc7...44b0`](https://explorer-studio.genlayer.com/transactions/0x5dc705756d8ccdce59023275813f9723d3be832842495ee669807f0989a944b0) | `FINALIZED` | `SUCCESS` | Tenant registers 1 unit; locks 100 wei collateral |
| **Adjudicate Critical Breach** | [`0x4a09...118b`](https://explorer-studio.genlayer.com/transactions/0x4a09bb37c2208f490d839195488757ac9014918b54bcacf873da3950b713118b) | `FINALIZED` | `SUCCESS` | `CRITICAL_BREACH`; 100 wei remedy + 5 wei stake refunded |
| **Claim Balance (Pull Payment)** | [`0xdf9b...ed22`](https://explorer-studio.genlayer.com/transactions/0xdf9b86d0751edc1426a7b9e379428a03f334ac881299d983cab48c2424dbed22) | `FINALIZED` | `SUCCESS` | Tenant withdraws 105 wei claimable balance |
| **Adjudicate Scheduled Maintenance** | [`0x042a...86ed`](https://explorer-studio.genlayer.com/transactions/0x042a33afb677b8b1f7cfb592c256a0932a06721270975cc3ba7505c5558586ed) | `FINALIZED` | `SUCCESS` | `CARVEOUT_SCHEDULED_MAINTENANCE` verified -> `NO_BREACH`; 5 wei stake forfeited |
| **Block Unverified Maintenance Abuse** | [`0x5683...181b`](https://explorer-studio.genlayer.com/transactions/0x568343a42f3f6abc9112cfafea7f300a2861fa3880ee4ecd28619a6909a9181b) | `FINALIZED` | `SUCCESS` | Unverified timestamps fail carveout -> `REPORT_INCONCLUSIVE`; stake held |
| **Guard 1: Unauthorized Caller** | [`0xd468...89d9c`](https://explorer-studio.genlayer.com/transactions/0xd468360ec3a18b3590b6e2de53a8bb202d837f70099a6f39ccde78f808d89d9c) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:ONLY_PROVIDER` |
| **Guard 2: Replay Duplicate Evidence** | [`0x811b...9f75`](https://explorer-studio.genlayer.com/transactions/0x811bf29e6989627303374df827494bfac330ecb1a21a53f1cc821304bba09f75) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:DUPLICATE_EVIDENCE_URL` |
| **Guard 3: Unauthorized Domain** | [`0x9e93...4e6b`](https://explorer-studio.genlayer.com/transactions/0x9e933f4241793f5637ab6f7b17e72900e4ed7ce193d22258b5af23184f84e46b) | `FINALIZED` | `ERROR` | `EXPECTED FAILURE`: `EXPECTED:DOMAIN_NOT_ALLOWED` |
