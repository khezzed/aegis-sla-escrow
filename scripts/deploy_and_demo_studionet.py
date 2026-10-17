import hashlib
import json
import pathlib
import subprocess
import sys
import time
from datetime import datetime, timezone
from genlayer_py import create_account, create_client
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionHashVariant, TransactionStatus

ENDPOINT = "https://studio.genlayer.com/api"
EXPLORER_BASE = "https://explorer-studio.genlayer.com"
EXPECTED_BLOB_SHA1 = "530d77e45959a9d94f9bd7672eaa59b0b8b077e8"

CHARTER_DICT = {
    "schema_version": "1.0",
    "service_name": "aegis-core-api",
    "allowed_telemetry_domains": [
        "raw.githubusercontent.com",
        "status.aegis-cloud.io",
    ],
    "allow_subdomains": True,
    "coverage_window_seconds": 86400,
    "claim_reporting_grace_seconds": 3600,
    "max_reevaluation_window_seconds": 7200,
    "max_retries": 2,
    "max_payload_bytes": 16384,
    "slos": {
        "SLO_RECOVERY_TIME": {
            "metric": "RECOVERY_TIME_MINUTES",
            "degraded_at_or_above_minutes": 15,
            "critical_at_or_above_minutes": 45,
        },
        "SLO_LATENCY_P99": {
            "metric": "LATENCY_P99_MS",
            "degraded_at_or_above_ms": 400,
            "critical_at_or_above_ms": 1200,
        },
    },
    "carveouts": {
        "CARVEOUT_SCHEDULED_MAINTENANCE": {
            "min_advance_notice_seconds": 86400,
            "max_maintenance_window_minutes": 120,
            "excused_slo_ids": [
                "SLO_RECOVERY_TIME",
                "SLO_LATENCY_P99",
            ],
        }
    },
    "evidence_requirements": {
        "require_finalized_postmortem": True,
        "require_incident_timestamps": True,
        "require_root_cause_statement": True,
    },
}

CTOR_ARGS = [
    json.dumps(CHARTER_DICT),
    10,   # unit_subscription_fee_wei
    100,  # unit_critical_remedy_wei
    40,   # unit_degraded_remedy_wei
    5,    # dispute_stake_wei
    10,   # max_units_per_subscription
]


def _install_resilient_rpc_retry(client) -> None:
    provider = getattr(client, "provider", None)
    if provider is None or getattr(provider, "_aegis_retry_installed", False):
        return
    orig_make_request = provider.make_request

    def make_request_with_retry(method, params):
        last_err = None
        for attempt in range(12):
            try:
                return orig_make_request(method, params)
            except Exception as err:
                last_err = err
                if attempt < 11:
                    time.sleep(3.0 * (attempt + 1))
                    continue
                raise
        raise last_err

    provider.make_request = make_request_with_retry
    provider._aegis_retry_installed = True


def _hex_hash(tx_hash) -> str:
    if isinstance(tx_hash, (bytes, bytearray)):
        h = tx_hash.hex()
    else:
        h = str(tx_hash)
    return h if h.startswith("0x") else f"0x{h}"


def _extract_receipt_summary(tx_hash_hex: str, receipt: dict, expected_failure: bool, label: str) -> dict:
    status_name = str(receipt.get("status_name", receipt.get("status", "")))
    consensus_data = receipt.get("consensus_data") or {}
    leader_receipts = consensus_data.get("leader_receipt") or []
    leader_exec = "UNKNOWN"
    leader_error = None
    if len(leader_receipts) > 0 and isinstance(leader_receipts[0], dict):
        leader_exec = str(leader_receipts[0].get("execution_result", "UNKNOWN"))
        genvm_res = leader_receipts[0].get("genvm_result") or {}
        leader_error = genvm_res.get("stderr") or leader_receipts[0].get("error")
    votes = consensus_data.get("votes") or {}
    return {
        "label": label,
        "tx_hash": tx_hash_hex,
        "explorer_url": f"{EXPLORER_BASE}/transactions/{tx_hash_hex}",
        "expected_failure": expected_failure,
        "status_name": status_name,
        "leader_execution_result": leader_exec,
        "leader_error": leader_error,
        "votes": votes,
    }


def _write_lf_json(path: pathlib.Path, data: dict) -> int:
    raw = (json.dumps(data, indent=2) + "\n").replace("\r\n", "\n").encode("utf-8")
    path.write_bytes(raw)
    return len(raw)


def main() -> None:
    contract_path = pathlib.Path("contracts/aegis_sla_escrow.py")
    raw_bytes = contract_path.read_bytes()
    if b"\r\n" in raw_bytes:
        raise RuntimeError("CRLF detected in contracts/aegis_sla_escrow.py; LF required")

    git_blob_header = f"blob {len(raw_bytes)}\0".encode("utf-8")
    computed_blob_sha1 = hashlib.sha1(git_blob_header + raw_bytes).hexdigest()
    if computed_blob_sha1 != EXPECTED_BLOB_SHA1:
        raise RuntimeError(
            f"Git blob SHA-1 mismatch: computed {computed_blob_sha1} != expected {EXPECTED_BLOB_SHA1}"
        )

    code_str = raw_bytes.decode("utf-8")
    runner_header = code_str.splitlines()[0].strip()

    provider_acct = create_account()
    tenant_acct = create_account()
    stranger_acct = create_account()

    client = create_client(chain=studionet, endpoint=ENDPOINT, account=provider_acct)
    _install_resilient_rpc_retry(client)

    print("Funding provider, tenant, and stranger accounts on studionet...")
    for acct in (provider_acct, tenant_acct, stranger_acct):
        client.fund_account(address=acct.address, amount=10**21)
    time.sleep(2)

    transactions_log = []

    def send_and_wait_tx(
        *,
        label: str,
        send_callable,
        expected_failure: bool = False,
        accept_retries: int = 80,
    ) -> tuple[dict, dict]:
        tx_hash = send_callable()
        tx_hex = _hex_hash(tx_hash)
        print(f"Waiting for ACCEPTED + FINALIZED on [{label}] ({tx_hex})...")
        accepted_receipt = client.wait_for_transaction_receipt(
            transaction_hash=tx_hex,
            status=TransactionStatus.ACCEPTED,
            interval=3000,
            retries=accept_retries,
        )
        accepted_status = str(accepted_receipt.get("status_name", accepted_receipt.get("status", "")))
        final_receipt = client.wait_for_transaction_receipt(
            transaction_hash=tx_hex,
            status=TransactionStatus.FINALIZED,
            interval=3000,
            retries=80,
        )
        summary = _extract_receipt_summary(tx_hex, final_receipt, expected_failure, label)
        summary["accepted_status_observed"] = accepted_status
        print(
            f"  -> status={summary['status_name']}, leader_execution_result={summary['leader_execution_result']}, expected_failure={expected_failure}"
        )
        if summary["status_name"] != "FINALIZED":
            raise RuntimeError(f"Transaction {tx_hex} did not reach FINALIZED: {summary['status_name']}")
        if not expected_failure and summary["leader_execution_result"] != "SUCCESS":
            raise RuntimeError(f"Expected SUCCESS on {label} ({tx_hex}), got: {summary}")
        if expected_failure and summary["leader_execution_result"] != "ERROR":
            raise RuntimeError(f"Expected ERROR on guard {label} ({tx_hex}), got: {summary}")
        transactions_log.append(summary)
        return summary, final_receipt

    # =========================================================================
    # Phase 1: Deploy Contract, Deposit Collateral, Register 3 Subscriptions
    # =========================================================================
    print("Deploying byte-identical LF AegisSlaEscrow to studionet...")
    deploy_summary, deploy_receipt = send_and_wait_tx(
        label="deploy_contract",
        send_callable=lambda: client.deploy_contract(
            code=code_str,
            account=provider_acct,
            args=CTOR_ARGS,
        ),
        expected_failure=False,
    )
    contract_address = deploy_receipt.get("recipient") or deploy_receipt.get("data", {}).get("contract_address")
    if not contract_address:
        raise RuntimeError(f"Could not extract contract_address from deploy receipt: {deploy_receipt}")
    print(f"Deployed contract address: {contract_address}")

    def read_fn(fn_name: str, args: list | None = None):
        return client.read_contract(
            address=contract_address,
            function_name=fn_name,
            args=args or [],
            account=provider_acct,
            transaction_hash_variant=TransactionHashVariant.LATEST_NONFINAL,
        )

    charter_info = read_fn("get_charter_info")
    acct_0 = read_fn("get_accounting_summary")
    deploy_summary["read_backs"] = {
        "get_charter_info": charter_info,
        "get_accounting_summary": acct_0,
    }
    assert acct_0["invariant_holds"] is True

    # Provider deposits 500 wei collateral
    send_and_wait_tx(
        label="deposit_collateral (500 wei)",
        send_callable=lambda: client.write_contract(
            address=contract_address,
            function_name="deposit_collateral",
            account=provider_acct,
            value=500,
            args=[],
        ),
        expected_failure=False,
    )
    acct_after_dep = read_fn("get_accounting_summary")
    transactions_log[-1]["read_backs"] = {"get_accounting_summary": acct_after_dep}
    assert acct_after_dep["free_collateral"] == 500
    assert acct_after_dep["invariant_holds"] is True

    # Tenant registers Subscriptions #1, #2, #3 (all unsimulated live transactions)
    sub_created_timestamps: dict[int, int] = {}
    for expected_sub_id in (1, 2, 3):
        send_and_wait_tx(
            label=f"register_subscription #{expected_sub_id} (1 unit, 10 wei fee)",
            send_callable=lambda: client.write_contract(
                address=contract_address,
                function_name="register_subscription",
                account=tenant_acct,
                value=10,
                args=[1],
            ),
            expected_failure=False,
        )
        sub_info = read_fn("get_subscription", [expected_sub_id])
        acct_sub = read_fn("get_accounting_summary")
        transactions_log[-1]["read_backs"] = {
            f"get_subscription({expected_sub_id})": sub_info,
            "get_accounting_summary": acct_sub,
        }
        assert sub_info["subscription_id"] == expected_sub_id
        assert sub_info["collateral_locked"] == 100
        assert acct_sub["invariant_holds"] is True
        sub_created_timestamps[expected_sub_id] = int(sub_info["created_at"])
        print(f"  Subscription #{expected_sub_id} created_at={sub_created_timestamps[expected_sub_id]}")

    # =========================================================================
    # Phase 2: Pin Telemetry Fixtures Aligned to On-Chain Subscription Windows
    # =========================================================================
    t1_start = sub_created_timestamps[1] + 1
    t1_end = t1_start + 60
    t2_start = sub_created_timestamps[2] + 1
    t2_end = t2_start + 60
    t3_start = sub_created_timestamps[3] + 1
    t3_end = t3_start + 60

    f1_path = pathlib.Path("fixtures/telemetry/inc-2026-crit-01.json")
    f2_path = pathlib.Path("fixtures/telemetry/inc-2026-maint-02.json")
    f3_path = pathlib.Path("fixtures/telemetry/inc-2026-unverified-maint-03.json")

    f1_bytes = _write_lf_json(
        f1_path,
        {
            "service": "aegis-core-api",
            "incident_id": "INC-2026-CRIT-01",
            "status": "FINALIZED_POSTMORTEM",
            "root_cause": "BGP route leak in primary ingress cluster caused severe packet drop.",
            "incident_start_ts": t1_start,
            "incident_end_ts": t1_end,
            "observed_ttr_minutes": 1,
            "observed_p99_ms": 1450,
            "maintenance_claimed": False,
            "maintenance_announced_ts": 0,
            "maintenance_window_start_ts": 0,
            "maintenance_window_end_ts": 0,
            "ttr_summary": "Total recovery duration was 1 minute from outage start to restoration",
            "p99_summary": "Peak p99 latency reached 1450 ms during the incident window",
        },
    )
    f2_bytes = _write_lf_json(
        f2_path,
        {
            "service": "aegis-core-api",
            "incident_id": "INC-2026-MAINT-02",
            "status": "FINALIZED_POSTMORTEM",
            "root_cause": "Scheduled database storage engine upgrade completed inside pre-announced maintenance window.",
            "incident_start_ts": t2_start,
            "incident_end_ts": t2_end,
            "observed_ttr_minutes": 1,
            "observed_p99_ms": 600,
            "maintenance_claimed": True,
            "maintenance_announced_ts": t2_start - 90000,
            "maintenance_window_start_ts": t2_start - 1,
            "maintenance_window_end_ts": t2_start + 1800,
            "ttr_summary": "Scheduled maintenance recovery took 1 minute inside declared window",
            "p99_summary": "Peak p99 latency was 600 ms during maintenance upgrade",
        },
    )
    f3_bytes = _write_lf_json(
        f3_path,
        {
            "service": "aegis-core-api",
            "incident_id": "INC-2026-UNVERIFIED-MAINT-03",
            "status": "FINALIZED_POSTMORTEM",
            "root_cause": "Unannounced emergency node reboot labeled as maintenance without advance notice timestamps.",
            "incident_start_ts": t3_start,
            "incident_end_ts": t3_end,
            "observed_ttr_minutes": 1,
            "observed_p99_ms": 1500,
            "maintenance_claimed": True,
            "maintenance_announced_ts": 0,
            "maintenance_window_start_ts": 0,
            "maintenance_window_end_ts": 0,
            "ttr_summary": "Outage recovery duration was 1 minute during emergency node reboot",
            "p99_summary": "Peak p99 latency reached 1500 ms during reboot",
        },
    )

    print("Committing and pushing telemetry fixtures to main for immutable raw.githubusercontent.com URLs...")
    subprocess.run(["git", "add", str(f1_path), str(f2_path), str(f3_path)], check=True)
    subprocess.run(
        ["git", "commit", "-m", f"Pin live telemetry fixture timestamps for studionet contract {contract_address}"],
        check=True,
    )
    subprocess.run(["git", "push", "origin", "main"], check=True)
    commit_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    head_contract_blob = subprocess.check_output(
        ["git", "rev-parse", "HEAD:contracts/aegis_sla_escrow.py"], text=True
    ).strip()
    assert head_contract_blob == computed_blob_sha1

    raw_base = f"https://raw.githubusercontent.com/khezzed/aegis-sla-escrow/{commit_sha}/fixtures/telemetry"
    url_crit_01 = f"{raw_base}/inc-2026-crit-01.json"
    url_maint_02 = f"{raw_base}/inc-2026-maint-02.json"
    url_unverified_03 = f"{raw_base}/inc-2026-unverified-maint-03.json"

    print(f"Pinned commit SHA: {commit_sha}")
    # Ensure 65s have elapsed since Sub #3 creation so t3_end <= adjudicate_ts on chain
    print("Waiting 45s to ensure incident_end_ts <= live block timestamp and CDN availability...")
    time.sleep(45)

    for label_f, u in (
        ("inc-2026-crit-01.json", url_crit_01),
        ("inc-2026-maint-02.json", url_maint_02),
        ("inc-2026-unverified-maint-03.json", url_unverified_03),
    ):
        curl_out = subprocess.check_output(
            ["curl.exe", "-s", "-o", "NUL", "-w", "%{http_code} %{size_download}", u],
            text=True,
        ).strip()
        print(f"  curl verify {label_f}: {curl_out} ({u})")
        if not curl_out.startswith("200 "):
            raise RuntimeError(f"Fixture {u} not HTTP 200: {curl_out}")

    # =========================================================================
    # Phase 3: Live On-Chain Adjudications & Pull-Payment Settlement
    # =========================================================================

    # 4. Mechanism Demo Part A: Submit + Adjudicate Critical Breach (Sub #1, Report #1) + Pull-Payment Claim
    send_and_wait_tx(
        label="submit_incident_report #1 (INC-2026-CRIT-01, 5 wei stake)",
        send_callable=lambda: client.write_contract(
            address=contract_address,
            function_name="submit_incident_report",
            account=tenant_acct,
            value=5,
            args=[1, "INC-2026-CRIT-01", url_crit_01],
        ),
        expected_failure=False,
    )
    transactions_log[-1]["read_backs"] = {
        "get_incident_report(1)": read_fn("get_incident_report", [1]),
        "get_accounting_summary": read_fn("get_accounting_summary"),
    }

    send_and_wait_tx(
        label="adjudicate_incident #1 (CRITICAL_BREACH via commit-pinned telemetry)",
        send_callable=lambda: client.write_contract(
            address=contract_address,
            function_name="adjudicate_incident",
            account=provider_acct,
            value=0,
            args=[1],
        ),
        expected_failure=False,
        accept_retries=90,
    )
    rep1_after = read_fn("get_incident_report", [1])
    sub1_after = read_fn("get_subscription", [1])
    claimable_before_pull = int(read_fn("get_claimable_balance", [tenant_acct.address]))
    acct_after_adj1 = read_fn("get_accounting_summary")
    transactions_log[-1]["read_backs"] = {
        "get_incident_report(1)": rep1_after,
        "get_subscription(1)": sub1_after,
        "get_claimable_balance(tenant)": claimable_before_pull,
        "get_accounting_summary": acct_after_adj1,
    }
    print("  Adjudication #1 readback:", json.dumps(rep1_after["adjudication"]))
    assert rep1_after["adjudication"]["outcome"] == "CRITICAL_BREACH"
    assert rep1_after["remedy_payout"] == 100
    assert rep1_after["stake_state"] == 1  # STAKE_REFUNDED
    assert claimable_before_pull == 105
    assert acct_after_adj1["invariant_holds"] is True

    send_and_wait_tx(
        label="claim_balance (tenant withdraws 105 wei: 100 wei remedy + 5 wei stake refund)",
        send_callable=lambda: client.write_contract(
            address=contract_address,
            function_name="claim_balance",
            account=tenant_acct,
            value=0,
            args=[],
        ),
        expected_failure=False,
    )
    claimable_after_pull = int(read_fn("get_claimable_balance", [tenant_acct.address]))
    acct_after_claim = read_fn("get_accounting_summary")
    transactions_log[-1]["read_backs"] = {
        "get_claimable_balance(tenant)": claimable_after_pull,
        "get_accounting_summary": acct_after_claim,
    }
    assert claimable_after_pull == 0
    assert acct_after_claim["total_outbound_wei"] == 105
    assert acct_after_claim["invariant_holds"] is True

    # 5. Mechanism Demo Part B: Verified Scheduled Maintenance Carve-Out Excusal (Sub #2, Report #2)
    send_and_wait_tx(
        label="submit_incident_report #2 (INC-2026-MAINT-02, 5 wei stake)",
        send_callable=lambda: client.write_contract(
            address=contract_address,
            function_name="submit_incident_report",
            account=tenant_acct,
            value=5,
            args=[2, "INC-2026-MAINT-02", url_maint_02],
        ),
        expected_failure=False,
    )
    transactions_log[-1]["read_backs"] = {
        "get_incident_report(2)": read_fn("get_incident_report", [2]),
        "get_accounting_summary": read_fn("get_accounting_summary"),
    }

    send_and_wait_tx(
        label="adjudicate_incident #2 (NO_BREACH via verified CARVEOUT_SCHEDULED_MAINTENANCE)",
        send_callable=lambda: client.write_contract(
            address=contract_address,
            function_name="adjudicate_incident",
            account=provider_acct,
            value=0,
            args=[2],
        ),
        expected_failure=False,
        accept_retries=90,
    )
    rep2_after = read_fn("get_incident_report", [2])
    sub2_after = read_fn("get_subscription", [2])
    acct_after_adj2 = read_fn("get_accounting_summary")
    transactions_log[-1]["read_backs"] = {
        "get_incident_report(2)": rep2_after,
        "get_subscription(2)": sub2_after,
        "get_accounting_summary": acct_after_adj2,
    }
    print("  Adjudication #2 readback:", json.dumps(rep2_after["adjudication"]))
    assert rep2_after["adjudication"]["outcome"] == "NO_BREACH"
    assert rep2_after["adjudication"]["carveout_ids"] == "CARVEOUT_SCHEDULED_MAINTENANCE"
    assert rep2_after["adjudication"]["status_code"] == "EXPECTED:CARVEOUT_APPLIES"
    assert rep2_after["stake_state"] == 2  # STAKE_FORFEITED
    assert acct_after_adj2["provider_fee_revenue"] == 35  # 30 wei fees + 5 wei forfeited stake
    assert acct_after_adj2["invariant_holds"] is True

    # 6. Abuse Blocked Demo: Unverified Maintenance Claim Blocked by Gate 6 (Sub #3, Report #3)
    send_and_wait_tx(
        label="submit_incident_report #3 (INC-2026-UNVERIFIED-MAINT-03, 5 wei stake)",
        send_callable=lambda: client.write_contract(
            address=contract_address,
            function_name="submit_incident_report",
            account=tenant_acct,
            value=5,
            args=[3, "INC-2026-UNVERIFIED-MAINT-03", url_unverified_03],
        ),
        expected_failure=False,
    )
    transactions_log[-1]["read_backs"] = {
        "get_incident_report(3)": read_fn("get_incident_report", [3]),
        "get_accounting_summary": read_fn("get_accounting_summary"),
    }

    send_and_wait_tx(
        label="adjudicate_incident #3 (Abuse blocked: unverified maintenance claim -> INCONCLUSIVE / STAKE_HELD)",
        send_callable=lambda: client.write_contract(
            address=contract_address,
            function_name="adjudicate_incident",
            account=provider_acct,
            value=0,
            args=[3],
        ),
        expected_failure=False,
        accept_retries=90,
    )
    rep3_after = read_fn("get_incident_report", [3])
    acct_after_adj3 = read_fn("get_accounting_summary")
    transactions_log[-1]["read_backs"] = {
        "get_incident_report(3)": rep3_after,
        "get_accounting_summary": acct_after_adj3,
    }
    print("  Adjudication #3 readback:", json.dumps(rep3_after["adjudication"]))
    assert rep3_after["adjudication"]["outcome"] == "INCONCLUSIVE"
    assert rep3_after["adjudication"]["status_code"] == "EXPECTED:UNVERIFIED_CARVEOUT_EVIDENCE"
    assert rep3_after["adjudication"]["maintenance_claimed"] is True
    assert rep3_after["status"] == 2  # REPORT_INCONCLUSIVE
    assert rep3_after["stake_state"] == 0  # STAKE_HELD
    assert acct_after_adj3["invariant_holds"] is True

    # =========================================================================
    # Phase 4: Deliberate Guard Triggers (EXPECTED FAILURES)
    # =========================================================================
    # Guard 1: Unauthorized caller attempting provider withdrawal
    send_and_wait_tx(
        label="EXPECTED FAILURE: Unauthorized caller on withdraw_free_collateral (EXPECTED:ONLY_PROVIDER)",
        send_callable=lambda: client.write_contract(
            address=contract_address,
            function_name="withdraw_free_collateral",
            account=stranger_acct,
            value=0,
            args=[10],
        ),
        expected_failure=True,
    )
    transactions_log[-1]["read_backs"] = {
        "get_accounting_summary": read_fn("get_accounting_summary"),
    }

    # Guard 2: Replay of already-used evidence URL on reevaluate_incident_report
    send_and_wait_tx(
        label="EXPECTED FAILURE: Replay of duplicate telemetry URL on reevaluate_incident_report (EXPECTED:DUPLICATE_EVIDENCE_URL)",
        send_callable=lambda: client.write_contract(
            address=contract_address,
            function_name="reevaluate_incident_report",
            account=tenant_acct,
            value=0,
            args=[3, url_unverified_03],
        ),
        expected_failure=True,
    )
    transactions_log[-1]["read_backs"] = {
        "get_incident_report(3)": read_fn("get_incident_report", [3]),
    }

    # Guard 3: Forged / unauthorized telemetry host on reevaluate_incident_report
    send_and_wait_tx(
        label="EXPECTED FAILURE: Unauthorized telemetry domain on reevaluate_incident_report (EXPECTED:UNAUTHORIZED_TELEMETRY_HOST)",
        send_callable=lambda: client.write_contract(
            address=contract_address,
            function_name="reevaluate_incident_report",
            account=tenant_acct,
            value=0,
            args=[3, "https://untrusted-spoofed-host.example.com/telemetry.json"],
        ),
        expected_failure=True,
    )
    final_acct = read_fn("get_accounting_summary")
    transactions_log[-1]["read_backs"] = {
        "get_accounting_summary": final_acct,
    }
    assert final_acct["invariant_holds"] is True

    manifest = {
        "project": "AEGIS — Autonomous Evidence-Grounded Incident & SLA Escrow",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "network": {
            "name": "studionet",
            "rpc_endpoint": ENDPOINT,
            "explorer_base_url": EXPLORER_BASE,
        },
        "source_verification": {
            "repository_url": "https://github.com/khezzed/aegis-sla-escrow",
            "contract_path": "contracts/aegis_sla_escrow.py",
            "deployed_commit_sha": commit_sha,
            "pinned_contract_url": f"https://github.com/khezzed/aegis-sla-escrow/blob/{commit_sha}/contracts/aegis_sla_escrow.py",
            "git_blob_sha1": computed_blob_sha1,
            "byte_length": len(raw_bytes),
            "line_endings": "LF",
            "runner_header": runner_header,
        },
        "toolchain": {
            "python_version": sys.version.split()[0],
            "genlayer_test": "0.29.2",
            "genlayer_py": "0.22.1",
            "genvm_linter": "0.3.2",
        },
        "evidence_fixtures": [
            {
                "incident_id": "INC-2026-CRIT-01",
                "url": url_crit_01,
                "http_status": 200,
                "raw_bytes": f1_bytes,
                "max_payload_bytes_cap": 16384,
            },
            {
                "incident_id": "INC-2026-MAINT-02",
                "url": url_maint_02,
                "http_status": 200,
                "raw_bytes": f2_bytes,
                "max_payload_bytes_cap": 16384,
            },
            {
                "incident_id": "INC-2026-UNVERIFIED-MAINT-03",
                "url": url_unverified_03,
                "http_status": 200,
                "raw_bytes": f3_bytes,
                "max_payload_bytes_cap": 16384,
            },
        ],
        "deployment": {
            "contract_address": contract_address,
            "explorer_contract_url": f"{EXPLORER_BASE}/address/{contract_address}",
            "provider_address": provider_acct.address,
            "tenant_address": tenant_acct.address,
            "unauthorized_stranger_address": stranger_acct.address,
            "constructor_args": {
                "charter": CHARTER_DICT,
                "unit_subscription_fee_wei": 10,
                "unit_critical_remedy_wei": 100,
                "unit_degraded_remedy_wei": 40,
                "dispute_stake_wei": 5,
                "max_units_per_subscription": 10,
            },
        },
        "transactions": transactions_log,
        "operator_notes": [
            {
                "earlier_attempt_contract": "0x3041d871A54477a47c1666ad21ab59f0B24EeFCA",
                "note": "Superseded attempt where SimConfig(genvm_datetime=...) was passed without mock validators on studionet; replaced by 100% unsimulated live wall-clock execution on this contract.",
            }
        ],
        "final_accounting_summary": final_acct,
    }

    manifest_path = pathlib.Path("release_manifest.json")
    manifest_path.write_bytes(json.dumps(manifest, indent=2).replace("\r\n", "\n").encode("utf-8"))
    print(f"Successfully wrote {manifest_path} for contract {contract_address}!")


if __name__ == "__main__":
    main()
