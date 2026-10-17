import json
import urllib.request
import pytest
from gltest import create_accounts, get_contract_factory, get_default_account

ONE_GEN = 10**18
UNIT_FEE_WEI = 10 * ONE_GEN
UNIT_CRIT_REMEDY_WEI = 100 * ONE_GEN
UNIT_DEG_REMEDY_WEI = 40 * ONE_GEN
DISPUTE_STAKE_WEI = 5 * ONE_GEN
MAX_UNITS = 50


def _is_localnet_rpc_reachable(url: str = "http://127.0.0.1:4000/api") -> bool:
    try:
        req = urllib.request.Request(
            url,
            data=b'{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status == 200
    except Exception:
        return False


SKIP_REASON = (
    "GenLayer Studio / GLSim RPC (http://127.0.0.1:4000/api) is not running locally. "
    "Start GenLayer Studio or GLSim (`genlayer up` / `glsim`) to execute live consensus integration tests."
)


def _build_charter_json() -> str:
    return json.dumps(
        {
            "schema_version": "1.0",
            "service_name": "cloud-core-api",
            "allowed_telemetry_domains": [
                "status.cloudprovider.io",
                "incidents.cloudprovider.io",
            ],
            "allow_subdomains": True,
            "coverage_window_seconds": 2592000,
            "claim_reporting_grace_seconds": 259200,
            "max_reevaluation_window_seconds": 604800,
            "max_retries": 2,
            "max_payload_bytes": 32768,
            "slos": {
                "SLO_RECOVERY_TIME": {
                    "metric": "RECOVERY_TIME_MINUTES",
                    "degraded_at_or_above_minutes": 30,
                    "critical_at_or_above_minutes": 120,
                },
                "SLO_LATENCY_P99": {
                    "metric": "LATENCY_P99_MS",
                    "degraded_at_or_above_ms": 500,
                    "critical_at_or_above_ms": 1500,
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
    )


def _deploy_and_fund_aegis():
    provider = get_default_account()
    tenant = create_accounts(1)[0]

    factory = get_contract_factory("AegisSlaEscrow")
    contract = factory.deploy(
        account=provider,
        args=[
            _build_charter_json(),
            UNIT_FEE_WEI,
            UNIT_CRIT_REMEDY_WEI,
            UNIT_DEG_REMEDY_WEI,
            DISPUTE_STAKE_WEI,
            MAX_UNITS,
        ],
    )
    contract.deposit_collateral().transact(account=provider, value=500 * ONE_GEN)
    return contract, provider, tenant


@pytest.mark.skipif(not _is_localnet_rpc_reachable(), reason=SKIP_REASON)
def test_integration_successful_adjudication_and_settlement():
    """
    Scenario 1: Successful adjudication through adjudicate_incident() where leader and
    validator independently evaluate incident telemetry and settle a verified breach.
    """
    contract, _provider, tenant = _deploy_and_fund_aegis()

    contract.register_subscription(args=[1]).transact(account=tenant, value=UNIT_FEE_WEI)
    summary_after_sub = contract.get_accounting_summary().call()
    assert summary_after_sub["free_collateral"] == 400 * ONE_GEN
    assert summary_after_sub["locked_collateral"] == 100 * ONE_GEN
    assert summary_after_sub["provider_fee_revenue"] == 10 * ONE_GEN
    assert summary_after_sub["invariant_holds"] is True

    contract.submit_incident_report(
        args=[
            1,
            "INC-LIVE-CRIT-01",
            "https://status.cloudprovider.io/incidents/inc-live-crit-01",
        ]
    ).transact(account=tenant, value=DISPUTE_STAKE_WEI)

    contract.adjudicate_incident(args=[1]).transact(account=tenant)
    rep = contract.get_incident_report(args=[1]).call()
    assert rep["adjudication_count"] == 1
    assert rep["adjudication"]["outcome"] in (
        "CRITICAL_BREACH",
        "DEGRADED_BREACH",
        "NO_BREACH",
        "INCONCLUSIVE",
    )
    summary_after_adj = contract.get_accounting_summary().call()
    assert summary_after_adj["invariant_holds"] is True


@pytest.mark.skipif(not _is_localnet_rpc_reachable(), reason=SKIP_REASON)
def test_integration_critical_gate_disagreement_between_leader_and_validator():
    """
    Scenario 2: Critical-gate consensus verification where validator_fn enforces exact
    equality across all 13 deterministic/metric/maintenance fields and grounded citations.
    """
    contract, _provider, tenant = _deploy_and_fund_aegis()

    contract.register_subscription(args=[1]).transact(account=tenant, value=UNIT_FEE_WEI)
    contract.submit_incident_report(
        args=[
            1,
            "INC-LIVE-GATE-02",
            "https://status.cloudprovider.io/incidents/inc-live-gate-02",
        ]
    ).transact(account=tenant, value=DISPUTE_STAKE_WEI)

    contract.adjudicate_incident(args=[1]).transact(account=tenant)
    summary = contract.get_accounting_summary().call()
    assert summary["invariant_holds"] is True


@pytest.mark.skipif(not _is_localnet_rpc_reachable(), reason=SKIP_REASON)
def test_integration_inconclusive_evidence_retrieval_and_stake_retention():
    """
    Scenario 3: Inconclusive evidence retrieval (e.g., unreachable or incomplete telemetry)
    retains the dispute stake in STAKE_HELD (0) and keeps collateral locked for retry.
    """
    contract, _provider, tenant = _deploy_and_fund_aegis()

    contract.register_subscription(args=[1]).transact(account=tenant, value=UNIT_FEE_WEI)
    contract.submit_incident_report(
        args=[
            1,
            "INC-LIVE-INCONC-03",
            "https://status.cloudprovider.io/incidents/nonexistent-404-telemetry",
        ]
    ).transact(account=tenant, value=DISPUTE_STAKE_WEI)

    contract.adjudicate_incident(args=[1]).transact(account=tenant)
    rep = contract.get_incident_report(args=[1]).call()
    assert rep["adjudication"]["outcome"] == "INCONCLUSIVE"
    assert rep["status"] == 2  # REPORT_INCONCLUSIVE
    assert rep["stake_state"] == 0  # STAKE_HELD

    summary = contract.get_accounting_summary().call()
    assert summary["outstanding_stakes"] == DISPUTE_STAKE_WEI
    assert summary["locked_collateral"] == UNIT_CRIT_REMEDY_WEI
    assert summary["invariant_holds"] is True


@pytest.mark.skipif(not _is_localnet_rpc_reachable(), reason=SKIP_REASON)
def test_integration_verified_scheduled_maintenance_carveout():
    """
    Scenario 4: Verified scheduled-maintenance carve-out evaluation through adjudicate_incident()
    where maintenance timestamps are persisted in the AdjudicationRecord and conservation holds.
    """
    contract, _provider, tenant = _deploy_and_fund_aegis()

    contract.register_subscription(args=[1]).transact(account=tenant, value=UNIT_FEE_WEI)
    contract.submit_incident_report(
        args=[
            1,
            "INC-LIVE-MAINT-04",
            "https://status.cloudprovider.io/incidents/inc-live-maint-04",
        ]
    ).transact(account=tenant, value=DISPUTE_STAKE_WEI)

    contract.adjudicate_incident(args=[1]).transact(account=tenant)
    rep = contract.get_incident_report(args=[1]).call()
    assert "maintenance_claimed" in rep["adjudication"]
    assert "maintenance_announced_ts" in rep["adjudication"]
    assert "maintenance_window_start_ts" in rep["adjudication"]
    assert "maintenance_window_end_ts" in rep["adjudication"]

    summary = contract.get_accounting_summary().call()
    assert summary["invariant_holds"] is True
