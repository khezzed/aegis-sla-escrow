import json
import pytest
from genlayer import u256
from contracts.aegis_sla_escrow import (
    AegisSlaEscrow,
    OUTCOME_CRITICAL_BREACH,
    OUTCOME_DEGRADED_BREACH,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_NO_BREACH,
    REPORT_INCONCLUSIVE,
    REPORT_RESOLVED,
    STAKE_FORFEITED,
    STAKE_HELD,
    STAKE_REFUNDED,
    STATUS_EXPECTED_CARVEOUT,
    STATUS_EXPECTED_UNVERIFIED_CARVEOUT,
    STATUS_EXTERNAL_OVERSIZED,
    STATUS_EXTERNAL_REDIRECT,
    STATUS_OK_VERIFIED,
    SUB_CLAIM_OPEN,
    SUB_RESOLVED,
)
from tests.direct.conftest import (
    DISPUTE_STAKE_WEI,
    MAX_UNITS,
    MockWebResponse,
    ONE_GEN,
    PROVIDER_ADDR,
    TENANT_A_ADDR,
    UNIT_CRIT_REMEDY_WEI,
    UNIT_DEG_REMEDY_WEI,
    UNIT_FEE_WEI,
    UserError,
    build_valid_charter_dict,
    gl_mock,
    mock_llm_responses,
    mock_web_responses,
)
from tests.direct.test_charter_and_accounting import (
    assert_global_conservation,
    deploy_default_contract,
)


def setup_funded_subscription(charter_override: dict | None = None) -> tuple[AegisSlaEscrow, u256]:
    gl_mock.message.sender_address = PROVIDER_ADDR
    gl_mock.message.value = u256(0)
    charter_dict = charter_override if charter_override is not None else build_valid_charter_dict()
    contract = AegisSlaEscrow(
        json.dumps(charter_dict),
        UNIT_FEE_WEI,
        UNIT_CRIT_REMEDY_WEI,
        UNIT_DEG_REMEDY_WEI,
        DISPUTE_STAKE_WEI,
        MAX_UNITS,
    )
    gl_mock.message.value = u256(500 * ONE_GEN)
    contract.deposit_collateral()

    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = UNIT_FEE_WEI
    sub_id = contract.register_subscription(u256(1))
    gl_mock.message.value = u256(0)
    return contract, sub_id


def test_at04_and_at12_url_canonicalization_and_duplicate_history_guard():
    contract, sub_id = setup_funded_subscription()

    # AT-04: Reject http://, spoofed domain prefix, port numbers, fragments, userinfo, path traversal
    invalid_urls = [
        "http://status.cloudprovider.io/incidents/inc-1",
        "https://evil-status.cloudprovider.io/incidents/inc-1",
        "https://status.cloudprovider.io.attacker.com/incidents/inc-1",
        "https://status.cloudprovider.io:8443/incidents/inc-1",
        "https://status.cloudprovider.io:443/incidents/inc-1",
        "https://admin@status.cloudprovider.io/incidents/inc-1",
        "https://status.cloudprovider.io/incidents/inc-1#section",
        "https://status.cloudprovider.io/incidents/../secret",
    ]
    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = DISPUTE_STAKE_WEI
    for bad_url in invalid_urls:
        with pytest.raises(UserError):
            contract.submit_incident_report(sub_id, "INC-URL-01", bad_url)

    # Submit URL with mixed-case scheme/host, duplicate slashes, and trailing slash
    raw_url = "  HTTPS://API.STATUS.CLOUDPROVIDER.IO//v1//incidents/inc-url-01/  "
    expected_canonical = "https://api.status.cloudprovider.io/v1/incidents/inc-url-01"
    rep_id = contract.submit_incident_report(sub_id, "INC-URL-01", raw_url)
    gl_mock.message.value = u256(0)

    rep_info = contract.get_incident_report(rep_id)
    assert rep_info["telemetry_url"] == expected_canonical
    assert rep_info["submitted_urls"] == [expected_canonical]

    # Trigger an HTTP 503 so the report enters REPORT_INCONCLUSIVE
    mock_web_responses[expected_canonical] = MockWebResponse(status=503, body=b"Service Unavailable")
    env = contract.adjudicate_incident(rep_id)
    assert env["outcome"] == OUTCOME_INCONCLUSIVE
    assert contract.get_incident_report(rep_id)["status"] == int(REPORT_INCONCLUSIVE)

    # AT-12: Reevaluating with any URL that normalizes to the same canonical string must revert
    gl_mock.message.sender_address = TENANT_A_ADDR
    with pytest.raises(UserError, match="EXPECTED:DUPLICATE_EVIDENCE_URL"):
        contract.reevaluate_incident_report(
            rep_id,
            "https://api.status.cloudprovider.io/v1/incidents/inc-url-01",
        )
    with pytest.raises(UserError, match="EXPECTED:DUPLICATE_EVIDENCE_URL"):
        contract.reevaluate_incident_report(
            rep_id,
            "HTTPS://api.status.cloudprovider.io///v1/incidents/inc-url-01/",
        )

    # Distinct canonical URL succeeds and appends to submitted_urls
    second_url = "https://incidents.cloudprovider.io/postmortems/inc-url-01-final.json"
    contract.reevaluate_incident_report(rep_id, second_url)
    rep_after = contract.get_incident_report(rep_id)
    assert rep_after["telemetry_url"] == second_url
    assert rep_after["submitted_urls"] == [expected_canonical, second_url]
    assert rep_after["retry_count"] == 1
    assert_global_conservation(contract)


def test_at05_http_redirect_and_oversized_payload_handling():
    contract, sub_id = setup_funded_subscription()
    url_redirect = "https://status.cloudprovider.io/incidents/inc-302"
    url_oversized = "https://status.cloudprovider.io/incidents/inc-big"

    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = DISPUTE_STAKE_WEI
    rep_id = contract.submit_incident_report(sub_id, "INC-HTTP-05", url_redirect)
    gl_mock.message.value = u256(0)

    # 1. HTTP 302 redirect rejected as INCONCLUSIVE (EXTERNAL:REDIRECT_DISALLOWED)
    mock_web_responses[url_redirect] = MockWebResponse(status=302, body=b"Redirecting")
    env_1 = contract.adjudicate_incident(rep_id)
    assert env_1["outcome"] == OUTCOME_INCONCLUSIVE
    assert env_1["status_code"] == STATUS_EXTERNAL_REDIRECT

    rep_1 = contract.get_incident_report(rep_id)
    assert rep_1["status"] == int(REPORT_INCONCLUSIVE)
    assert rep_1["stake_state"] == int(STAKE_HELD)
    assert rep_1["stake_escrowed"] == int(DISPUTE_STAKE_WEI)
    assert_global_conservation(contract)

    # 2. Retry with oversized payload (> 32768 bytes) -> INCONCLUSIVE (EXTERNAL:PAYLOAD_OVERSIZED)
    contract.reevaluate_incident_report(rep_id, url_oversized)
    mock_web_responses[url_oversized] = MockWebResponse(status=200, body=b"X" * 33000)
    env_2 = contract.adjudicate_incident(rep_id)
    assert env_2["outcome"] == OUTCOME_INCONCLUSIVE
    assert env_2["status_code"] == STATUS_EXTERNAL_OVERSIZED
    assert contract.get_incident_report(rep_id)["stake_state"] == int(STAKE_HELD)
    assert_global_conservation(contract)


def test_at07_unverified_carveout_returns_inconclusive_never_no_breach():
    contract, sub_id = setup_funded_subscription()
    url = "https://status.cloudprovider.io/incidents/inc-unverified-maint"

    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = DISPUTE_STAKE_WEI
    rep_id = contract.submit_incident_report(sub_id, "INC-MAINT-UNVERIFIED", url)
    gl_mock.message.value = u256(0)

    payload = (
        '{"service":"cloud-core-api","incident_id":"INC-MAINT-UNVERIFIED",'
        '"status":"finalized","ttr_note":"Total recovery time was 150 minutes",'
        '"p99_note":"Peak p99 latency reached 1800 ms","maintenance":"scheduled maintenance claimed without window timestamps"}'
    )
    mock_web_responses[url] = MockWebResponse(status=200, body=payload.encode("utf-8"))
    mock_llm_responses.append(
        lambda _p: {
            "service_name_matched": True,
            "incident_id_matched": True,
            "postmortem_finalized": True,
            "timestamps_present": True,
            "root_cause_documented": True,
            "incident_start_ts": 1792232000,
            "incident_end_ts": 1792241000,  # 150 minutes
            "observed_ttr_minutes": 150,
            "observed_p99_ms": 1800,
            "maintenance_claimed": True,
            "maintenance_announced_ts": 0,  # Missing announcement timestamp!
            "maintenance_window_start_ts": 0,
            "maintenance_window_end_ts": 0,
            "ttr_citation": "Total recovery time was 150 minutes",
            "p99_citation": "Peak p99 latency reached 1800 ms",
        }
    )

    gl_mock.message_raw = {"datetime": 1792250000}
    env = contract.adjudicate_incident(rep_id)
    assert env["outcome"] == OUTCOME_INCONCLUSIVE
    assert env["status_code"] == STATUS_EXPECTED_UNVERIFIED_CARVEOUT
    assert env["maintenance_claimed"] is True
    assert env["telemetry_complete"] is False

    rep = contract.get_incident_report(rep_id)
    assert rep["status"] == int(REPORT_INCONCLUSIVE)
    assert rep["stake_state"] == int(STAKE_HELD)
    assert_global_conservation(contract)


def test_at08a_failed_maintenance_carveout_on_critical_incident_resolves_critical():
    """
    AT-08a: Critical incident (TTR=180m >= 120m) claims scheduled maintenance,
    but maintenance was announced only 2 hours in advance (< 24h min_advance_notice_seconds).
    The failed carve-out is rejected and the active CRITICAL SLO violation produces CRITICAL_BREACH.
    """
    contract, sub_id = setup_funded_subscription()
    url = "https://status.cloudprovider.io/incidents/inc-crit-bad-maint"

    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = DISPUTE_STAKE_WEI
    rep_id = contract.submit_incident_report(sub_id, "INC-CRIT-MAINT-FAIL", url)
    gl_mock.message.value = u256(0)

    inc_start = 1792232000
    inc_end = inc_start + (180 * 60)  # 180 minutes (CRITICAL TTR)
    maint_start = inc_start
    maint_end = inc_end
    maint_announced = maint_start - 7200  # Only 2 hours notice (< 86400s required)

    payload = (
        '{"service":"cloud-core-api","incident_id":"INC-CRIT-MAINT-FAIL",'
        '"ttr":"observed_ttr_minutes: 180","p99":"observed_p99_ms: 350"}'
    )
    mock_web_responses[url] = MockWebResponse(status=200, body=payload.encode("utf-8"))
    mock_llm_responses.append(
        lambda _p: {
            "service_name_matched": True,
            "incident_id_matched": True,
            "postmortem_finalized": True,
            "timestamps_present": True,
            "root_cause_documented": True,
            "incident_start_ts": inc_start,
            "incident_end_ts": inc_end,
            "observed_ttr_minutes": 180,
            "observed_p99_ms": 350,
            "maintenance_claimed": True,
            "maintenance_announced_ts": maint_announced,
            "maintenance_window_start_ts": maint_start,
            "maintenance_window_end_ts": maint_end,
            "ttr_citation": "observed_ttr_minutes: 180",
            "p99_citation": "observed_p99_ms: 350",
        }
    )

    gl_mock.message_raw = {"datetime": inc_end + 600}
    env = contract.adjudicate_incident(rep_id)
    assert env["outcome"] == OUTCOME_CRITICAL_BREACH
    assert env["status_code"] == STATUS_OK_VERIFIED
    assert env["violated_slo_ids"] == "SLO_RECOVERY_TIME"
    assert env["carveout_ids"] == ""
    assert env["maintenance_claimed"] is True
    assert env["maintenance_announced_ts"] == maint_announced

    rep = contract.get_incident_report(rep_id)
    assert rep["status"] == int(REPORT_RESOLVED)
    assert rep["stake_state"] == int(STAKE_REFUNDED)
    assert rep["remedy_payout"] == int(UNIT_CRIT_REMEDY_WEI)
    assert int(contract.get_claimable_balance(str(TENANT_A_ADDR))) == int(UNIT_CRIT_REMEDY_WEI + DISPUTE_STAKE_WEI)
    assert_global_conservation(contract)


def test_at08b_failed_maintenance_carveout_on_degraded_incident_resolves_degraded():
    """
    AT-08b: Degraded incident (TTR=45m, p99=600ms — both in DEGRADED tier, below CRITICAL)
    claims scheduled maintenance, but the outage extended 15 minutes past maintenance_window_end_ts.
    A failed maintenance exception does NOT imply a critical breach; it leaves the measured
    DEGRADED violations active and settles as DEGRADED_BREACH.
    """
    contract, sub_id = setup_funded_subscription()
    url = "https://status.cloudprovider.io/incidents/inc-deg-bad-maint"

    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = DISPUTE_STAKE_WEI
    rep_id = contract.submit_incident_report(sub_id, "INC-DEG-MAINT-FAIL", url)
    gl_mock.message.value = u256(0)

    maint_start = 1792232000
    maint_end = maint_start + (30 * 60)      # 30-minute declared window
    maint_announced = maint_start - 100000   # >= 24h notice
    inc_start = maint_start
    inc_end = maint_start + (45 * 60)        # Spilled 15 minutes past maint_end! (45m DEGRADED TTR)

    payload = (
        '{"service":"cloud-core-api","incident_id":"INC-DEG-MAINT-FAIL",'
        '"ttr":"recovery took 45 minutes","p99":"p99 latency was 600 ms"}'
    )
    mock_web_responses[url] = MockWebResponse(status=200, body=payload.encode("utf-8"))
    mock_llm_responses.append(
        lambda _p: {
            "service_name_matched": True,
            "incident_id_matched": True,
            "postmortem_finalized": True,
            "timestamps_present": True,
            "root_cause_documented": True,
            "incident_start_ts": inc_start,
            "incident_end_ts": inc_end,
            "observed_ttr_minutes": 45,
            "observed_p99_ms": 600,
            "maintenance_claimed": True,
            "maintenance_announced_ts": maint_announced,
            "maintenance_window_start_ts": maint_start,
            "maintenance_window_end_ts": maint_end,
            "ttr_citation": "recovery took 45 minutes",
            "p99_citation": "p99 latency was 600 ms",
        }
    )

    gl_mock.message_raw = {"datetime": inc_end + 600}
    env = contract.adjudicate_incident(rep_id)
    assert env["outcome"] == OUTCOME_DEGRADED_BREACH
    assert env["status_code"] == STATUS_OK_VERIFIED
    assert env["violated_slo_ids"] == "SLO_LATENCY_P99,SLO_RECOVERY_TIME"
    assert env["carveout_ids"] == ""

    rep = contract.get_incident_report(rep_id)
    assert rep["status"] == int(REPORT_RESOLVED)
    assert rep["stake_state"] == int(STAKE_REFUNDED)
    assert rep["remedy_payout"] == int(UNIT_DEG_REMEDY_WEI)
    assert int(contract.get_claimable_balance(str(TENANT_A_ADDR))) == int(UNIT_DEG_REMEDY_WEI + DISPUTE_STAKE_WEI)

    summary = assert_global_conservation(contract)
    # 500 GEN initial - 40 GEN degraded remedy = 460 GEN free collateral (60 GEN unused unlocked)
    assert summary["free_collateral"] == 460 * ONE_GEN
    assert summary["locked_collateral"] == 0


def test_at09_and_at10_scoped_and_full_maintenance_carveout_excusal():
    # AT-09: Charter where maintenance only excuses SLO_RECOVERY_TIME, NOT SLO_LATENCY_P99
    scoped_charter = build_valid_charter_dict()
    scoped_charter["carveouts"]["CARVEOUT_SCHEDULED_MAINTENANCE"]["excused_slo_ids"] = ["SLO_RECOVERY_TIME"]
    contract_scoped, sub_scoped = setup_funded_subscription(scoped_charter)

    url_scoped = "https://status.cloudprovider.io/incidents/inc-scoped-maint"
    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = DISPUTE_STAKE_WEI
    rep_scoped = contract_scoped.submit_incident_report(sub_scoped, "INC-SCOPED-MAINT", url_scoped)
    gl_mock.message.value = u256(0)

    maint_start = 1792232000
    maint_end = maint_start + (90 * 60)      # 90m window (<= 120m max)
    maint_announced = maint_start - 90000    # > 24h notice
    inc_start = maint_start + 300
    inc_end = inc_start + (60 * 60)          # 60m outage inside window (DEGRADED TTR)

    payload_scoped = (
        '{"service":"cloud-core-api","incident_id":"INC-SCOPED-MAINT",'
        '"ttr":"outage lasted 60 minutes","p99":"p99 latency spiked to 750 ms"}'
    )
    mock_web_responses[url_scoped] = MockWebResponse(status=200, body=payload_scoped.encode("utf-8"))
    mock_llm_responses.append(
        lambda _p: {
            "service_name_matched": True,
            "incident_id_matched": True,
            "postmortem_finalized": True,
            "timestamps_present": True,
            "root_cause_documented": True,
            "incident_start_ts": inc_start,
            "incident_end_ts": inc_end,
            "observed_ttr_minutes": 60,
            "observed_p99_ms": 750,  # DEGRADED latency (unexcused!)
            "maintenance_claimed": True,
            "maintenance_announced_ts": maint_announced,
            "maintenance_window_start_ts": maint_start,
            "maintenance_window_end_ts": maint_end,
            "ttr_citation": "outage lasted 60 minutes",
            "p99_citation": "p99 latency spiked to 750 ms",
        }
    )

    gl_mock.message_raw = {"datetime": maint_end + 600}
    env_scoped = contract_scoped.adjudicate_incident(rep_scoped)
    assert env_scoped["outcome"] == OUTCOME_DEGRADED_BREACH
    assert env_scoped["carveout_ids"] == "CARVEOUT_SCHEDULED_MAINTENANCE"
    assert env_scoped["violated_slo_ids"] == "SLO_LATENCY_P99,SLO_RECOVERY_TIME"
    assert_global_conservation(contract_scoped)

    # AT-10: Default charter where both SLO_RECOVERY_TIME and SLO_LATENCY_P99 are excused by valid maintenance
    gl_mock.message_raw = {"datetime": 1792231200}
    contract_full, sub_full = setup_funded_subscription()
    url_full = "https://status.cloudprovider.io/incidents/inc-valid-maint"
    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = DISPUTE_STAKE_WEI
    rep_full = contract_full.submit_incident_report(sub_full, "INC-VALID-MAINT", url_full)
    gl_mock.message.value = u256(0)

    mock_web_responses[url_full] = MockWebResponse(status=200, body=payload_scoped.encode("utf-8"))
    mock_llm_responses.clear()
    mock_llm_responses.append(
        lambda _p: {
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
            "ttr_citation": "outage lasted 60 minutes",
            "p99_citation": "p99 latency spiked to 750 ms",
        }
    )

    gl_mock.message_raw = {"datetime": maint_end + 600}
    env_full = contract_full.adjudicate_incident(rep_full)
    assert env_full["outcome"] == OUTCOME_NO_BREACH
    assert env_full["status_code"] == STATUS_EXPECTED_CARVEOUT
    assert env_full["carveout_ids"] == "CARVEOUT_SCHEDULED_MAINTENANCE"

    rep_full_info = contract_full.get_incident_report(rep_full)
    assert rep_full_info["status"] == int(REPORT_RESOLVED)
    assert rep_full_info["stake_state"] == int(STAKE_FORFEITED)
    assert rep_full_info["adjudication"]["maintenance_claimed"] is True
    assert rep_full_info["adjudication"]["maintenance_announced_ts"] == maint_announced
    assert rep_full_info["adjudication"]["maintenance_window_start_ts"] == maint_start
    assert rep_full_info["adjudication"]["maintenance_window_end_ts"] == maint_end
    assert_global_conservation(contract_full)
