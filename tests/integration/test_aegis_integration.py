import json
import time
import pytest
from gltest import create_accounts, get_contract_factory, get_gl_client, get_validator_factory

ONE_GEN = 10**18
UNIT_FEE_WEI = 10 * ONE_GEN
UNIT_CRIT_REMEDY_WEI = 100 * ONE_GEN
UNIT_DEG_REMEDY_WEI = 40 * ONE_GEN
DISPUTE_STAKE_WEI = 5 * ONE_GEN
MAX_UNITS = 50

SUB_CREATE_ISO = "2026-10-15T00:00:00Z"
SUB_CREATE_TS = 1792022400
REPORT_SUBMIT_ISO = "2026-10-15T04:00:00Z"
ADJUDICATE_ISO = "2026-10-15T05:00:00Z"
ADJUDICATE_RETRY_ISO = "2026-10-15T06:00:00Z"


def _install_resilient_rpc_retry(client) -> None:
    provider = getattr(client, "provider", None)
    if provider is None or getattr(provider, "_aegis_retry_installed", False):
        return
    orig_make_request = provider.make_request

    def make_request_with_retry(method, params):
        last_err = None
        for attempt in range(4):
            try:
                return orig_make_request(method, params)
            except Exception as err:
                last_err = err
                if attempt < 3 and "Request to " in str(err):
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise
        raise last_err

    provider.make_request = make_request_with_retry
    provider._aegis_retry_installed = True


def _ensure_rpc_available():
    client = get_gl_client()
    _install_resilient_rpc_retry(client)
    try:
        client.provider.make_request("eth_chainId", [])
    except Exception as exc:
        pytest.skip(
            f"GenLayer RPC endpoint ({getattr(client.provider, 'url', 'unknown')}) is not reachable: {exc}"
        )
    return client


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


def _build_adjudication_context(
    *,
    url: str,
    http_status: int,
    payload_body: str,
    incident_id: str,
    llm_extract: dict | None,
    genvm_datetime: str = ADJUDICATE_ISO,
    count: int = 5,
) -> dict:
    client = _ensure_rpc_available()
    web_mock = {
        "nondet_web_request": {
            url: {
                "method": "GET",
                "status": http_status,
                "body": payload_body,
            }
        }
    }
    llm_mock = (
        {"response": {f"Expected Incident ID: {incident_id}": json.dumps(llm_extract)}}
        if llm_extract is not None
        else {"response": {}}
    )

    try:
        res = client.provider.make_request("sim_getAllValidators", [])
        existing = res.get("result") or []
    except Exception:
        existing = []

    if existing:
        base_val = existing[0]
        base_plugin_cfg = dict(base_val.get("plugin_config") or {})
        base_plugin_cfg["mock_web_response"] = web_mock
        if llm_extract is not None:
            base_plugin_cfg["mock_response"] = llm_mock
        val_dict = {
            "stake": int(base_val.get("stake", 8)),
            "provider": base_val["provider"],
            "model": base_val["model"],
            "config": base_val.get("config", {}),
            "plugin": base_val["plugin"],
            "plugin_config": base_plugin_cfg,
        }
        return {
            "validators": [dict(val_dict) for _ in range(count)],
            "genvm_datetime": genvm_datetime,
        }

    vf = get_validator_factory()
    validators = vf.batch_create_mock_validators(
        count=count,
        mock_llm_response={"nondet_exec_prompt": llm_mock["response"]},
        mock_web_response=web_mock,
    )
    return {
        "validators": [v.to_dict() for v in validators],
        "genvm_datetime": genvm_datetime,
    }


def _deploy_and_fund_aegis():
    client = _ensure_rpc_available()
    provider, tenant = create_accounts(2)
    client.fund_account(address=provider.address, amount=2000 * ONE_GEN)
    client.fund_account(address=tenant.address, amount=500 * ONE_GEN)

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
        transaction_context={"genvm_datetime": SUB_CREATE_ISO},
    )
    contract.connect(provider).deposit_collateral().transact(
        value=500 * ONE_GEN,
        transaction_context={"genvm_datetime": SUB_CREATE_ISO},
    )
    return contract, provider, tenant


def test_integration_critical_breach_adjudication_and_settlement():
    """
    Scenario 1: Multi-validator consensus adjudication of a finalized post-mortem showing
    a 150-minute outage and 1850ms p99 latency settles as CRITICAL_BREACH, refunds the
    5 GEN dispute stake, credits 100 GEN critical remedy, and allows tenant withdrawal.
    """
    contract, _provider, tenant = _deploy_and_fund_aegis()

    contract.connect(tenant).register_subscription(args=[1]).transact(
        value=UNIT_FEE_WEI,
        transaction_context={"genvm_datetime": SUB_CREATE_ISO},
    )
    summary_after_sub = contract.get_accounting_summary().call()
    assert summary_after_sub["free_collateral"] == 400 * ONE_GEN
    assert summary_after_sub["locked_collateral"] == 100 * ONE_GEN
    assert summary_after_sub["provider_fee_revenue"] == 10 * ONE_GEN
    assert summary_after_sub["outstanding_stakes"] == 0
    assert summary_after_sub["total_claimable_balances"] == 0
    assert summary_after_sub["invariant_holds"] is True

    url = "https://status.cloudprovider.io/incidents/inc-live-crit-01"
    inc_id = "INC-LIVE-CRIT-01"
    contract.connect(tenant).submit_incident_report(
        args=[1, inc_id, url]
    ).transact(
        value=DISPUTE_STAKE_WEI,
        transaction_context={"genvm_datetime": REPORT_SUBMIT_ISO},
    )

    inc_start = SUB_CREATE_TS + 3600  # 1792026000
    inc_end = inc_start + (150 * 60)  # 1792035000 (150m >= 120m critical threshold)
    ttr_cit = "Total recovery time was 150 minutes from 1792026000 to 1792035000."
    p99_cit = "Peak p99 latency reached 1850 ms during the outage."
    payload_dict = {
        "service_name": "cloud-core-api",
        "incident_id": inc_id,
        "postmortem_status": "FINALIZED",
        "postmortem_finalized": True,
        "timestamps_present": True,
        "root_cause_documented": True,
        "root_cause": "Primary routing cluster fiber cut in us-east-1 caused 150 minutes of downtime.",
        "incident_start_ts": inc_start,
        "incident_end_ts": inc_end,
        "observed_ttr_minutes": 150,
        "observed_p99_ms": 1850,
        "maintenance_claimed": False,
        "maintenance_announced_ts": 0,
        "maintenance_window_start_ts": 0,
        "maintenance_window_end_ts": 0,
        "ttr_summary": ttr_cit,
        "p99_summary": p99_cit,
    }
    llm_extract = {
        "service_name_matched": True,
        "incident_id_matched": True,
        "postmortem_finalized": True,
        "timestamps_present": True,
        "root_cause_documented": True,
        "incident_start_ts": inc_start,
        "incident_end_ts": inc_end,
        "observed_ttr_minutes": 150,
        "observed_p99_ms": 1850,
        "maintenance_claimed": False,
        "maintenance_announced_ts": 0,
        "maintenance_window_start_ts": 0,
        "maintenance_window_end_ts": 0,
        "ttr_citation": ttr_cit,
        "p99_citation": p99_cit,
    }

    tx_ctx = _build_adjudication_context(
        url=url,
        http_status=200,
        payload_body=json.dumps(payload_dict),
        incident_id=inc_id,
        llm_extract=llm_extract,
        genvm_datetime=ADJUDICATE_ISO,
    )
    contract.connect(tenant).adjudicate_incident(args=[1]).transact(transaction_context=tx_ctx)

    rep = contract.get_incident_report(args=[1]).call()
    assert rep["adjudication_count"] == 1
    assert rep["status"] == 3  # REPORT_RESOLVED
    assert rep["stake_state"] == 1  # STAKE_REFUNDED
    assert rep["stake_escrowed"] == 0
    assert rep["remedy_payout"] == UNIT_CRIT_REMEDY_WEI
    assert rep["adjudication"]["outcome"] == "CRITICAL_BREACH"
    assert rep["adjudication"]["status_code"] == "OK:TELEMETRY_VERIFIED"
    assert rep["adjudication"]["telemetry_complete"] is True
    assert rep["adjudication"]["violated_slo_ids"] == "SLO_LATENCY_P99,SLO_RECOVERY_TIME"
    assert rep["adjudication"]["carveout_ids"] == ""

    summary = contract.get_accounting_summary().call()
    assert summary["free_collateral"] == 400 * ONE_GEN
    assert summary["locked_collateral"] == 0
    assert summary["provider_fee_revenue"] == 10 * ONE_GEN
    assert summary["outstanding_stakes"] == 0
    assert summary["total_claimable_balances"] == 105 * ONE_GEN
    assert summary["invariant_holds"] is True

    # Tenant claims the 105 GEN payout (100 GEN critical remedy + 5 GEN refunded dispute stake)
    contract.connect(tenant).claim_balance().transact(
        transaction_context={"genvm_datetime": ADJUDICATE_RETRY_ISO}
    )
    summary_after_claim = contract.get_accounting_summary().call()
    assert summary_after_claim["total_claimable_balances"] == 0
    assert summary_after_claim["total_outbound_wei"] == 105 * ONE_GEN
    assert summary_after_claim["invariant_holds"] is True


def test_integration_incident_identity_mismatch_is_inconclusive_and_retains_stake():
    """
    Scenario 2: When telemetry references a different incident_id than the filed claim,
    Gate 3 returns non-terminal INCONCLUSIVE (EXPECTED:INCIDENT_ID_MISMATCH) rather than
    NO_BREACH, retaining the tenant's stake in STAKE_HELD (0) and keeping the claim open for retry.
    """
    contract, _provider, tenant = _deploy_and_fund_aegis()

    contract.connect(tenant).register_subscription(args=[1]).transact(
        value=UNIT_FEE_WEI,
        transaction_context={"genvm_datetime": SUB_CREATE_ISO},
    )
    url = "https://status.cloudprovider.io/incidents/inc-live-gate-02"
    inc_id = "INC-LIVE-GATE-02"
    contract.connect(tenant).submit_incident_report(
        args=[1, inc_id, url]
    ).transact(
        value=DISPUTE_STAKE_WEI,
        transaction_context={"genvm_datetime": REPORT_SUBMIT_ISO},
    )

    inc_start = SUB_CREATE_TS + 3600
    inc_end = inc_start + (150 * 60)
    ttr_cit = "Total recovery time was 150 minutes."
    p99_cit = "Peak p99 latency reached 1850 ms."
    # Payload is for INC-WRONG-999, NOT INC-LIVE-GATE-02
    payload_dict = {
        "service_name": "cloud-core-api",
        "incident_id": "INC-WRONG-999",
        "postmortem_status": "FINALIZED",
        "postmortem_finalized": True,
        "timestamps_present": True,
        "root_cause_documented": True,
        "root_cause": "Database failover in eu-west-1.",
        "incident_start_ts": inc_start,
        "incident_end_ts": inc_end,
        "observed_ttr_minutes": 150,
        "observed_p99_ms": 1850,
        "maintenance_claimed": False,
        "maintenance_announced_ts": 0,
        "maintenance_window_start_ts": 0,
        "maintenance_window_end_ts": 0,
        "ttr_summary": ttr_cit,
        "p99_summary": p99_cit,
    }
    llm_extract = {
        "service_name_matched": True,
        "incident_id_matched": False,
        "postmortem_finalized": True,
        "timestamps_present": True,
        "root_cause_documented": True,
        "incident_start_ts": inc_start,
        "incident_end_ts": inc_end,
        "observed_ttr_minutes": 150,
        "observed_p99_ms": 1850,
        "maintenance_claimed": False,
        "maintenance_announced_ts": 0,
        "maintenance_window_start_ts": 0,
        "maintenance_window_end_ts": 0,
        "ttr_citation": ttr_cit,
        "p99_citation": p99_cit,
    }

    tx_ctx = _build_adjudication_context(
        url=url,
        http_status=200,
        payload_body=json.dumps(payload_dict),
        incident_id=inc_id,
        llm_extract=llm_extract,
        genvm_datetime=ADJUDICATE_ISO,
    )
    contract.connect(tenant).adjudicate_incident(args=[1]).transact(transaction_context=tx_ctx)

    rep = contract.get_incident_report(args=[1]).call()
    assert rep["adjudication"]["outcome"] == "INCONCLUSIVE"
    assert rep["adjudication"]["status_code"] == "EXPECTED:INCIDENT_MISMATCH"
    assert rep["adjudication"]["telemetry_complete"] is False
    assert rep["status"] == 2  # REPORT_INCONCLUSIVE (retryable, not terminal!)
    assert rep["stake_state"] == 0  # STAKE_HELD (not forfeited!)
    assert rep["stake_escrowed"] == DISPUTE_STAKE_WEI

    summary = contract.get_accounting_summary().call()
    assert summary["free_collateral"] == 400 * ONE_GEN
    assert summary["locked_collateral"] == 100 * ONE_GEN
    assert summary["provider_fee_revenue"] == 10 * ONE_GEN
    assert summary["outstanding_stakes"] == DISPUTE_STAKE_WEI
    assert summary["total_claimable_balances"] == 0
    assert summary["invariant_holds"] is True


def test_integration_inconclusive_http_404_and_reevaluation_to_degraded_breach():
    """
    Scenario 3: Initial telemetry URL returns HTTP 404 -> settles as INCONCLUSIVE
    (EXTERNAL:HTTP_NOT_FOUND) and retains stake in STAKE_HELD (0).
    Tenant submits a new canonical URL via reevaluate_incident_report() with a 45-minute
    degraded outage -> settles as DEGRADED_BREACH (40 GEN remedy + 5 GEN stake refund,
    60 GEN unused collateral unlocked to free_collateral).
    """
    contract, _provider, tenant = _deploy_and_fund_aegis()

    contract.connect(tenant).register_subscription(args=[1]).transact(
        value=UNIT_FEE_WEI,
        transaction_context={"genvm_datetime": SUB_CREATE_ISO},
    )
    url_404 = "https://status.cloudprovider.io/incidents/nonexistent-404-telemetry"
    inc_id = "INC-LIVE-INCONC-03"
    contract.connect(tenant).submit_incident_report(
        args=[1, inc_id, url_404]
    ).transact(
        value=DISPUTE_STAKE_WEI,
        transaction_context={"genvm_datetime": REPORT_SUBMIT_ISO},
    )

    tx_ctx_404 = _build_adjudication_context(
        url=url_404,
        http_status=404,
        payload_body="Not Found",
        incident_id=inc_id,
        llm_extract=None,
        genvm_datetime=ADJUDICATE_ISO,
    )
    contract.connect(tenant).adjudicate_incident(args=[1]).transact(transaction_context=tx_ctx_404)

    rep_mid = contract.get_incident_report(args=[1]).call()
    assert rep_mid["adjudication"]["outcome"] == "INCONCLUSIVE"
    assert rep_mid["adjudication"]["status_code"] == "EXTERNAL:HTTP_NOT_FOUND"
    assert rep_mid["status"] == 2  # REPORT_INCONCLUSIVE
    assert rep_mid["stake_state"] == 0  # STAKE_HELD

    summary_mid = contract.get_accounting_summary().call()
    assert summary_mid["outstanding_stakes"] == DISPUTE_STAKE_WEI
    assert summary_mid["locked_collateral"] == UNIT_CRIT_REMEDY_WEI
    assert summary_mid["invariant_holds"] is True

    # Re-evaluate with finalized post-mortem showing DEGRADED_BREACH (45m TTR, 600ms p99)
    url_deg = "https://incidents.cloudprovider.io/postmortems/inc-live-inconc-03-final"
    contract.connect(tenant).reevaluate_incident_report(
        args=[1, url_deg]
    ).transact(transaction_context={"genvm_datetime": ADJUDICATE_ISO})

    inc_start = SUB_CREATE_TS + 3600  # 1792026000
    inc_end = inc_start + (45 * 60)  # 1792028700 (45m in [30m, 120m) degraded tier)
    ttr_cit = "Total recovery time was 45 minutes from 1792026000 to 1792028700."
    p99_cit = "Peak p99 latency reached 600 ms during the incident."
    payload_deg = {
        "service_name": "cloud-core-api",
        "incident_id": inc_id,
        "postmortem_status": "FINALIZED",
        "postmortem_finalized": True,
        "timestamps_present": True,
        "root_cause_documented": True,
        "root_cause": "Cache tier saturation caused 45 minutes of degraded latency and recovery.",
        "incident_start_ts": inc_start,
        "incident_end_ts": inc_end,
        "observed_ttr_minutes": 45,
        "observed_p99_ms": 600,
        "maintenance_claimed": False,
        "maintenance_announced_ts": 0,
        "maintenance_window_start_ts": 0,
        "maintenance_window_end_ts": 0,
        "ttr_summary": ttr_cit,
        "p99_summary": p99_cit,
    }
    llm_deg = {
        "service_name_matched": True,
        "incident_id_matched": True,
        "postmortem_finalized": True,
        "timestamps_present": True,
        "root_cause_documented": True,
        "incident_start_ts": inc_start,
        "incident_end_ts": inc_end,
        "observed_ttr_minutes": 45,
        "observed_p99_ms": 600,
        "maintenance_claimed": False,
        "maintenance_announced_ts": 0,
        "maintenance_window_start_ts": 0,
        "maintenance_window_end_ts": 0,
        "ttr_citation": ttr_cit,
        "p99_citation": p99_cit,
    }

    tx_ctx_deg = _build_adjudication_context(
        url=url_deg,
        http_status=200,
        payload_body=json.dumps(payload_deg),
        incident_id=inc_id,
        llm_extract=llm_deg,
        genvm_datetime=ADJUDICATE_RETRY_ISO,
    )
    contract.connect(tenant).adjudicate_incident(args=[1]).transact(transaction_context=tx_ctx_deg)

    rep_final = contract.get_incident_report(args=[1]).call()
    assert rep_final["adjudication_count"] == 2
    assert rep_final["retry_count"] == 1
    assert rep_final["status"] == 3  # REPORT_RESOLVED
    assert rep_final["stake_state"] == 1  # STAKE_REFUNDED
    assert rep_final["remedy_payout"] == UNIT_DEG_REMEDY_WEI
    assert rep_final["adjudication"]["outcome"] == "DEGRADED_BREACH"
    assert rep_final["adjudication"]["status_code"] == "OK:TELEMETRY_VERIFIED"

    summary_final = contract.get_accounting_summary().call()
    # 60 GEN unused collateral unlocked back to free_collateral (400 + 60 = 460 GEN)
    assert summary_final["free_collateral"] == 460 * ONE_GEN
    assert summary_final["locked_collateral"] == 0
    assert summary_final["provider_fee_revenue"] == 10 * ONE_GEN
    assert summary_final["outstanding_stakes"] == 0
    assert summary_final["total_claimable_balances"] == 45 * ONE_GEN
    assert summary_final["invariant_holds"] is True


def test_integration_verified_scheduled_maintenance_carveout_resolves_no_breach():
    """
    Scenario 4: Verified scheduled-maintenance carve-out evaluation where maintenance was
    announced >= 24h in advance, window <= 120m, and the 60-minute incident is fully contained
    within the window. Excuses both SLOs, settles as NO_BREACH (EXPECTED:CARVEOUT_APPLIES),
    unlocks all 100 GEN collateral to free_collateral, and forfeits the 5 GEN stake to provider_fee_revenue.
    """
    contract, _provider, tenant = _deploy_and_fund_aegis()

    contract.connect(tenant).register_subscription(args=[1]).transact(
        value=UNIT_FEE_WEI,
        transaction_context={"genvm_datetime": SUB_CREATE_ISO},
    )
    url = "https://status.cloudprovider.io/incidents/inc-live-maint-04"
    inc_id = "INC-LIVE-MAINT-04"
    contract.connect(tenant).submit_incident_report(
        args=[1, inc_id, url]
    ).transact(
        value=DISPUTE_STAKE_WEI,
        transaction_context={"genvm_datetime": REPORT_SUBMIT_ISO},
    )

    maint_start = SUB_CREATE_TS + 3000  # 1792025400
    maint_end = maint_start + (90 * 60)  # 1792030800 (90m window <= 120m max)
    maint_announced = maint_start - 90000  # 1791935400 (25h advance notice >= 86400s required)
    inc_start = SUB_CREATE_TS + 3600  # 1792026000 (inside maintenance window)
    inc_end = inc_start + (60 * 60)  # 1792029600 (60m duration, inside maintenance window)
    ttr_cit = "Total recovery time was 60 minutes from 1792026000 to 1792029600."
    p99_cit = "Peak p99 latency reached 750 ms during the maintenance window."

    payload_dict = {
        "service_name": "cloud-core-api",
        "incident_id": inc_id,
        "postmortem_status": "FINALIZED",
        "postmortem_finalized": True,
        "timestamps_present": True,
        "root_cause_documented": True,
        "root_cause": "Planned control-plane database upgrade executed within scheduled maintenance window.",
        "incident_start_ts": inc_start,
        "incident_end_ts": inc_end,
        "observed_ttr_minutes": 60,
        "observed_p99_ms": 750,
        "maintenance_claimed": True,
        "maintenance_announced_ts": maint_announced,
        "maintenance_window_start_ts": maint_start,
        "maintenance_window_end_ts": maint_end,
        "ttr_summary": ttr_cit,
        "p99_summary": p99_cit,
    }
    llm_extract = {
        "service_name_matched": True,
        "incident_id_matched": True,
        "postmortem_finalized": True,
        "timestamps_present": True,
        "root_cause_documented": True,
        "incident_start_ts": inc_start,
        "incident_end_ts": inc_end,
        "observed_ttr_minutes": 60,
        "observed_p99_ms": 750,
        "maintenance_claimed": True,
        "maintenance_announced_ts": maint_announced,
        "maintenance_window_start_ts": maint_start,
        "maintenance_window_end_ts": maint_end,
        "ttr_citation": ttr_cit,
        "p99_citation": p99_cit,
    }

    tx_ctx = _build_adjudication_context(
        url=url,
        http_status=200,
        payload_body=json.dumps(payload_dict),
        incident_id=inc_id,
        llm_extract=llm_extract,
        genvm_datetime=ADJUDICATE_ISO,
    )
    contract.connect(tenant).adjudicate_incident(args=[1]).transact(transaction_context=tx_ctx)

    rep = contract.get_incident_report(args=[1]).call()
    assert rep["status"] == 3  # REPORT_RESOLVED
    assert rep["stake_state"] == 2  # STAKE_FORFEITED
    assert rep["stake_escrowed"] == 0
    assert rep["remedy_payout"] == 0
    assert rep["adjudication"]["outcome"] == "NO_BREACH"
    assert rep["adjudication"]["status_code"] == "EXPECTED:CARVEOUT_APPLIES"
    assert rep["adjudication"]["carveout_ids"] == "CARVEOUT_SCHEDULED_MAINTENANCE"
    assert rep["adjudication"]["violated_slo_ids"] == "SLO_LATENCY_P99,SLO_RECOVERY_TIME"
    assert rep["adjudication"]["maintenance_claimed"] is True
    assert rep["adjudication"]["maintenance_announced_ts"] == maint_announced
    assert rep["adjudication"]["maintenance_window_start_ts"] == maint_start
    assert rep["adjudication"]["maintenance_window_end_ts"] == maint_end

    summary = contract.get_accounting_summary().call()
    assert summary["free_collateral"] == 500 * ONE_GEN
    assert summary["locked_collateral"] == 0
    assert summary["provider_fee_revenue"] == 15 * ONE_GEN
    assert summary["outstanding_stakes"] == 0
    assert summary["total_claimable_balances"] == 0
    assert summary["invariant_holds"] is True
