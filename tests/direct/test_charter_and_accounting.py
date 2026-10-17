import json
import pytest
from genlayer import u256
from contracts.aegis_sla_escrow import (
    AegisSlaEscrow,
    REPORT_EXPIRED_INCONCLUSIVE,
    REPORT_OPEN,
    STAKE_HELD,
    STAKE_REFUNDED,
    SUB_ACTIVE,
    SUB_CLAIM_OPEN,
    SUB_EXPIRED,
    _safe_add_u256,
    _safe_mul_u256,
    _safe_sub_u256,
)
from tests.direct.conftest import (
    DISPUTE_STAKE_WEI,
    KEEPER_ADDR,
    MAX_UNITS,
    ONE_GEN,
    PROVIDER_ADDR,
    TENANT_A_ADDR,
    TENANT_B_ADDR,
    UNIT_CRIT_REMEDY_WEI,
    UNIT_DEG_REMEDY_WEI,
    UNIT_FEE_WEI,
    UserError,
    build_valid_charter_dict,
    emitted_transfers,
    gl_mock,
)


def deploy_default_contract() -> AegisSlaEscrow:
    gl_mock.message.sender_address = PROVIDER_ADDR
    gl_mock.message.value = u256(0)
    return AegisSlaEscrow(
        json.dumps(build_valid_charter_dict()),
        UNIT_FEE_WEI,
        UNIT_CRIT_REMEDY_WEI,
        UNIT_DEG_REMEDY_WEI,
        DISPUTE_STAKE_WEI,
        MAX_UNITS,
    )


def assert_global_conservation(contract: AegisSlaEscrow) -> dict:
    summary = contract.get_accounting_summary()
    assert summary["invariant_holds"] is True
    assert summary["bucket_sum_wei"] == summary["net_flows_wei"]
    assert int(contract.balance) == summary["bucket_sum_wei"]
    return summary


def test_constructor_validation_and_immutable_charter():
    contract = deploy_default_contract()
    info = contract.get_charter_info()
    assert info["provider"] == str(PROVIDER_ADDR)
    assert len(info["charter_hash"]) == 64
    assert info["unit_subscription_fee_wei"] == int(UNIT_FEE_WEI)
    assert_global_conservation(contract)

    # Reject value attached to constructor
    gl_mock.message.value = u256(100)
    with pytest.raises(UserError, match="EXPECTED:NON_PAYABLE_CTOR"):
        AegisSlaEscrow(
            json.dumps(build_valid_charter_dict()),
            UNIT_FEE_WEI,
            UNIT_CRIT_REMEDY_WEI,
            UNIT_DEG_REMEDY_WEI,
            DISPUTE_STAKE_WEI,
            MAX_UNITS,
        )
    gl_mock.message.value = u256(0)

    # Reject degraded_remedy >= critical_remedy
    with pytest.raises(UserError, match="EXPECTED:CRITICAL_MUST_EXCEED_DEGRADED_REMEDY"):
        AegisSlaEscrow(
            json.dumps(build_valid_charter_dict()),
            UNIT_FEE_WEI,
            UNIT_CRIT_REMEDY_WEI,
            UNIT_CRIT_REMEDY_WEI,
            DISPUTE_STAKE_WEI,
            MAX_UNITS,
        )

    # Reject invalid domain in charter (wildcard or uppercase or port)
    bad_charter = build_valid_charter_dict()
    bad_charter["allowed_telemetry_domains"] = ["*.cloudprovider.io"]
    with pytest.raises(UserError, match="EXPECTED:INVALID_TELEMETRY_DOMAIN"):
        AegisSlaEscrow(
            json.dumps(bad_charter),
            UNIT_FEE_WEI,
            UNIT_CRIT_REMEDY_WEI,
            UNIT_DEG_REMEDY_WEI,
            DISPUTE_STAKE_WEI,
            MAX_UNITS,
        )

    # Reject inverted SLO thresholds
    bad_slo = build_valid_charter_dict()
    bad_slo["slos"]["SLO_RECOVERY_TIME"]["critical_at_or_above_minutes"] = 15
    with pytest.raises(UserError, match="EXPECTED:INVALID_SLO_RECOVERY_TIME_THRESHOLDS"):
        AegisSlaEscrow(
            json.dumps(bad_slo),
            UNIT_FEE_WEI,
            UNIT_CRIT_REMEDY_WEI,
            UNIT_DEG_REMEDY_WEI,
            DISPUTE_STAKE_WEI,
            MAX_UNITS,
        )


def test_at01_payable_decorators_and_exact_payment_guards():
    contract = deploy_default_contract()

    # Verify @gl.public.write.payable attributes on only the 3 payable methods
    assert getattr(contract.deposit_collateral, "__gl_payable__", False) is True
    assert getattr(contract.register_subscription, "__gl_payable__", False) is True
    assert getattr(contract.submit_incident_report, "__gl_payable__", False) is True
    assert getattr(contract.adjudicate_incident, "__gl_payable__", False) is False
    assert getattr(contract.reevaluate_incident_report, "__gl_payable__", False) is False
    assert getattr(contract.withdraw_free_collateral, "__gl_payable__", False) is False

    # 1. Zero deposit rejected
    gl_mock.message.sender_address = PROVIDER_ADDR
    gl_mock.message.value = u256(0)
    with pytest.raises(UserError, match="EXPECTED:ZERO_DEPOSIT"):
        contract.deposit_collateral()

    # Non-provider deposit rejected
    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = u256(100 * ONE_GEN)
    with pytest.raises(UserError, match="EXPECTED:ONLY_PROVIDER"):
        contract.deposit_collateral()

    # Valid provider deposit of 500 GEN
    gl_mock.message.sender_address = PROVIDER_ADDR
    gl_mock.message.value = u256(500 * ONE_GEN)
    contract.deposit_collateral()
    summary = assert_global_conservation(contract)
    assert summary["free_collateral"] == 500 * ONE_GEN
    assert summary["total_inbound_wei"] == 500 * ONE_GEN

    # 2. Subscription with wrong fee (0, expected - 1, expected + 1) rejected
    gl_mock.message.sender_address = TENANT_A_ADDR
    expected_two_units_fee = 2 * int(UNIT_FEE_WEI)
    for bad_val in (0, expected_two_units_fee - 1, expected_two_units_fee + 1):
        gl_mock.message.value = u256(bad_val)
        with pytest.raises(UserError, match="EXPECTED:INCORRECT_FEE"):
            contract.register_subscription(u256(2))

    # Valid 2-unit subscription (20 GEN fee, locks 200 GEN collateral)
    gl_mock.message.value = u256(expected_two_units_fee)
    sub_id = contract.register_subscription(u256(2))
    assert int(sub_id) == 1
    summary = assert_global_conservation(contract)
    assert summary["free_collateral"] == 300 * ONE_GEN
    assert summary["locked_collateral"] == 200 * ONE_GEN
    assert summary["provider_fee_revenue"] == 20 * ONE_GEN
    assert summary["total_inbound_wei"] == 520 * ONE_GEN

    # 3. Incident report with wrong stake (0, stake - 1, stake + 1) rejected
    for bad_stake in (0, int(DISPUTE_STAKE_WEI) - 1, int(DISPUTE_STAKE_WEI) + 1):
        gl_mock.message.value = u256(bad_stake)
        with pytest.raises(UserError, match="EXPECTED:INCORRECT_STAKE"):
            contract.submit_incident_report(
                sub_id,
                "INC-2026-001",
                "https://status.cloudprovider.io/incidents/inc-2026-001",
            )
    assert_global_conservation(contract)


def test_at02_and_at03_single_claim_per_subscription_and_duplicate_incident_guard():
    contract = deploy_default_contract()
    gl_mock.message.sender_address = PROVIDER_ADDR
    gl_mock.message.value = u256(500 * ONE_GEN)
    contract.deposit_collateral()

    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = UNIT_FEE_WEI
    sub_1 = contract.register_subscription(u256(1))
    sub_2 = contract.register_subscription(u256(1))

    # Submit first report on sub_1
    gl_mock.message.value = DISPUTE_STAKE_WEI
    rep_1 = contract.submit_incident_report(
        sub_1,
        "inc-2026-101",
        "https://status.cloudprovider.io/incidents/101",
    )
    assert int(rep_1) == 1
    assert_global_conservation(contract)

    # AT-02: Second incident report on the same subscription (sub_1) must revert
    gl_mock.message.value = DISPUTE_STAKE_WEI
    with pytest.raises(UserError, match="EXPECTED:SUBSCRIPTION_ALREADY_CLAIMED"):
        contract.submit_incident_report(
            sub_1,
            "inc-2026-102",
            "https://status.cloudprovider.io/incidents/102",
        )

    # AT-03: Same tenant submitting the same incident_id (case-insensitive) on sub_2 must revert
    gl_mock.message.value = DISPUTE_STAKE_WEI
    with pytest.raises(UserError, match="EXPECTED:DUPLICATE_INCIDENT_FOR_TENANT"):
        contract.submit_incident_report(
            sub_2,
            "INC-2026-101",
            "https://status.cloudprovider.io/incidents/101-v2",
        )

    # Different tenant (TENANT_B_ADDR) CAN report the same outage on their own subscription
    gl_mock.message.sender_address = TENANT_B_ADDR
    gl_mock.message.value = UNIT_FEE_WEI
    sub_b = contract.register_subscription(u256(1))
    gl_mock.message.value = DISPUTE_STAKE_WEI
    rep_b = contract.submit_incident_report(
        sub_b,
        "INC-2026-101",
        "https://status.cloudprovider.io/incidents/101",
    )
    assert int(rep_b) == 2
    assert_global_conservation(contract)


def test_subscription_expiry_and_stale_report_finalization_boundaries():
    contract = deploy_default_contract()
    gl_mock.message.sender_address = PROVIDER_ADDR
    gl_mock.message.value = u256(300 * ONE_GEN)
    contract.deposit_collateral()

    # Register sub_1 (unclaimed) and sub_2 (claimed but stale)
    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = UNIT_FEE_WEI
    sub_1 = contract.register_subscription(u256(1))
    sub_2 = contract.register_subscription(u256(1))

    sub1_info = contract.get_subscription(sub_1)
    report_deadline = sub1_info["report_deadline"]

    # Boundary check: at t_now == report_deadline, release_expired_subscription must revert
    gl_mock.message.value = u256(0)
    gl_mock.message_raw = {"datetime": report_deadline}
    with pytest.raises(UserError, match="EXPECTED:GRACE_PERIOD_ACTIVE"):
        contract.release_expired_subscription(sub_1)

    # File report on sub_2 right at the exact report_deadline boundary (allowed: t_now <= report_deadline)
    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = DISPUTE_STAKE_WEI
    rep_2 = contract.submit_incident_report(
        sub_2,
        "INC-BOUNDARY-1",
        "https://status.cloudprovider.io/incidents/boundary-1",
    )
    assert contract.get_subscription(sub_2)["status"] == int(SUB_CLAIM_OPEN)

    # Advance clock by 1 second past report_deadline
    gl_mock.message.value = u256(0)
    gl_mock.message_raw = {"datetime": report_deadline + 1}

    # sub_1 (unclaimed) can now be released
    contract.release_expired_subscription(sub_1)
    assert contract.get_subscription(sub_1)["status"] == int(SUB_EXPIRED)
    assert contract.get_subscription(sub_1)["collateral_locked"] == 0

    # sub_2 has an open report, so release_expired_subscription on sub_2 must revert
    with pytest.raises(UserError, match="EXPECTED:SUBSCRIPTION_NOT_ACTIVE"):
        contract.release_expired_subscription(sub_2)

    # Check finalize_stale_report boundary on rep_2
    rep2_info = contract.get_incident_report(rep_2)
    reeval_deadline = rep2_info["reevaluation_deadline"]
    gl_mock.message_raw = {"datetime": reeval_deadline}
    with pytest.raises(UserError, match="EXPECTED:REEVALUATION_WINDOW_STILL_ACTIVE"):
        contract.finalize_stale_report(rep_2)

    # Advance 1 second past reevaluation_deadline: anyone (e.g. keeper) can finalize stale report
    gl_mock.message.sender_address = KEEPER_ADDR
    gl_mock.message_raw = {"datetime": reeval_deadline + 1}
    contract.finalize_stale_report(rep_2)

    rep2_after = contract.get_incident_report(rep_2)
    assert rep2_after["status"] == int(REPORT_EXPIRED_INCONCLUSIVE)
    assert rep2_after["stake_state"] == int(STAKE_REFUNDED)
    assert rep2_after["stake_escrowed"] == 0
    assert int(contract.get_claimable_balance(str(TENANT_A_ADDR))) == int(DISPUTE_STAKE_WEI)

    summary = assert_global_conservation(contract)
    assert summary["locked_collateral"] == 0
    assert summary["free_collateral"] == 300 * ONE_GEN
    assert summary["outstanding_stakes"] == 0
    assert summary["total_claimable_balances"] == int(DISPUTE_STAKE_WEI)


def test_provider_and_tenant_withdrawals_and_flow_counters():
    contract = deploy_default_contract()
    gl_mock.message.sender_address = PROVIDER_ADDR
    gl_mock.message.value = u256(250 * ONE_GEN)
    contract.deposit_collateral()

    gl_mock.message.sender_address = TENANT_A_ADDR
    gl_mock.message.value = UNIT_FEE_WEI
    sub_id = contract.register_subscription(u256(1))
    gl_mock.message.value = u256(0)

    # Provider cannot withdraw locked collateral (100 GEN locked, 150 GEN free)
    gl_mock.message.sender_address = PROVIDER_ADDR
    with pytest.raises(UserError, match="EXPECTED:INSUFFICIENT_FREE_COLLATERAL"):
        contract.withdraw_free_collateral(u256(151 * ONE_GEN))

    # Provider withdraws 50 GEN free collateral and 10 GEN fee revenue
    contract.withdraw_free_collateral(u256(50 * ONE_GEN))
    contract.withdraw_fee_revenue(UNIT_FEE_WEI)
    assert len(emitted_transfers) == 2
    assert emitted_transfers[0].recipient == PROVIDER_ADDR
    assert int(emitted_transfers[0].value) == 50 * ONE_GEN
    assert int(emitted_transfers[1].value) == int(UNIT_FEE_WEI)

    summary = assert_global_conservation(contract)
    assert summary["free_collateral"] == 100 * ONE_GEN
    assert summary["locked_collateral"] == 100 * ONE_GEN
    assert summary["provider_fee_revenue"] == 0
    assert summary["total_inbound_wei"] == 260 * ONE_GEN
    assert summary["total_outbound_wei"] == 60 * ONE_GEN


def test_safe_u256_arithmetic_bounds():
    max_val = (1 << 256) - 1
    assert int(_safe_add_u256(max_val - 10, 10)) == max_val
    with pytest.raises(UserError, match="EXPECTED:U256_OVERFLOW"):
        _safe_add_u256(max_val, 1)
    with pytest.raises(UserError, match="EXPECTED:U256_OVERFLOW"):
        _safe_mul_u256(1 << 128, 1 << 128)
    with pytest.raises(UserError, match="EXPECTED:U256_UNDERFLOW"):
        _safe_sub_u256(5, 6)
